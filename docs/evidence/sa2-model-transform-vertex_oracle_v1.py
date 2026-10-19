from pathlib import Path
import csv,hashlib,json,math,struct,time
from collections import Counter
from fractions import Fraction
from functools import lru_cache

OUT=Path(__file__).resolve().parent
WORK=OUT.parent
MASK=0xffffffff
sha=lambda b:hashlib.sha256(b).hexdigest()
with (OUT/'parsed-original-words.csv').open(newline='') as f:
    INSTRUCTIONS={int(r['original_virtual_address'],0):r for r in csv.DictReader(f) if int(r['owner'],0) in (0x8011da30,0x8011daf0)}

class Unsupported(Exception):pass

def signed(v,bits=32):return v-(1<<bits) if v&(1<<(bits-1)) else v
def bitsof(v):return int.from_bytes(struct.pack('>f',v),'big')

@lru_cache(None)
def rational(bits):
    exponent=(bits>>23)&255;sign=-1 if bits&0x80000000 else 1;mantissa=bits&0x7fffff
    if exponent==255:raise Unsupported(f'consumed nonfinite binary32 {bits:08x}')
    if exponent:mantissa|=1<<23;power=exponent-150
    else:power=-149
    return Fraction(sign*mantissa*(1<<power),1) if power>=0 else Fraction(sign*mantissa,1<<(-power))

def nearest_integer(p,q):
    n,r=divmod(p,q)
    return n+int(r*2>q or (r*2==q and n&1))

def rounded_bits(value,zero_sign=0):
    if value==0:return zero_sign
    sign=0x80000000 if value<0 else 0;p,q=abs(value.numerator),value.denominator
    exponent=p.bit_length()-q.bit_length()
    if (p<q<<exponent if exponent>=0 else p<<(-exponent)<q):exponent-=1
    if exponent<-126:return sign|nearest_integer(p<<149,q)
    shift=23-exponent
    n=nearest_integer(p<<shift,q) if shift>=0 else nearest_integer(p,q<<(-shift))
    if n==1<<24:n>>=1;exponent+=1
    if exponent>127:raise Unsupported('rounded binary32 overflow')
    return sign|((exponent+127)<<23)|(n-(1<<23))

@lru_cache(None)
def mul(a,c):return rounded_bits(rational(a)*rational(c),(a^c)&0x80000000)

@lru_cache(None)
def fma(a,c,b):
    product=rational(a)*rational(c);addend=rational(b)
    both_negative_zero=product==0 and addend==0 and ((a^c)&0x80000000) and (b&0x80000000)
    return rounded_bits(product+addend,0x80000000 if both_negative_zero else 0)

def ftz(bits):return bits&0x80000000 if bits&0x7f800000==0 else bits

class Machine:
    def __init__(self,caseid,opcode,count,start,input_bytes,input_offset,matrix_bytes,before):
        self.caseid=caseid;self.opcode=opcode;self.count=count;self.start=start
        self.input_offset=input_offset;self.stride=16 if opcode==0x23 else 24
        self.regions=[('matrix',0x10000000,bytearray(matrix_bytes)),('input',0x20000000,bytearray(input_bytes)),('scratch',0x30000000,bytearray(before)),('stack',0x40000000,bytearray(4096)),('descriptor',0x50000000,bytearray(struct.pack('>III',0x30000000+start*32,0x20000000+input_offset,count)))]
        self.r=[0]*32;self.r[1]=0x40000800;self.r[3]=0x50000000;self.r[4]=0x10000000
        self.ps=[[0,0] for _ in range(32)];self.ctr=0;self.eq=False;self.pc=0x8011da30 if opcode==0x23 else 0x8011daf0
        self.coverage=Counter();self.loads=[];self.stores=[];self.operations=[];self.step=0;self.written=set()
    def region(self,address,n):
        for name,base,buf in self.regions:
            if base<=address and address+n<=base+len(buf):return name,base,buf,address-base
        raise Unsupported(f'unmapped memory {address:#x}+{n} at {self.pc:#x}')
    def read(self,address,n,kind):
        name,base,buf,off=self.region(address,n);value=bytes(buf[off:off+n])
        if kind not in ('stack',):
            relative=off-self.input_offset if name=='input' else off
            self.loads.append({'case_id':self.caseid,'step':self.step,'va':hex(self.pc),'kind':kind,'region':name,'relative_offset':relative,'size':n,'raw_hex':value.hex(),'unused_final_preload':name=='input' and relative>=self.count*self.stride})
        return value
    def write(self,address,value,kind):
        name,base,buf,off=self.region(address,len(value));buf[off:off+len(value)]=value
        if name=='scratch':
            self.written.update(range(off,off+len(value)))
            self.stores.append({'case_id':self.caseid,'step':self.step,'va':hex(self.pc),'kind':kind,'scratch_offset':off,'size':len(value),'raw_hex':value.hex()})
    def execute(self,maxsteps=200000):
        while True:
            if self.step>=maxsteps:raise Unsupported('bounded instruction limit')
            if self.pc not in INSTRUCTIONS:raise Unsupported(f'unsupported instruction address {self.pc:#x}')
            row=INSTRUCTIONS[self.pc];w=int(row['word'],0);pc=self.pc;nextpc=(pc+4)&MASK
            self.step+=1;self.coverage[hex(pc)]+=1
            op,d,a,b,c=w>>26,w>>21&31,w>>16&31,w>>11&31,w>>6&31;xo=w>>1&1023
            imm=signed(w&0xffff,16);ea=((self.r[a] if a else 0)+imm)&MASK
            if op==32:self.r[d]=int.from_bytes(self.read(ea,4,'lwz'),'big')
            elif op==33:self.r[d]=int.from_bytes(self.read(ea,4,'raw_lwzu'),'big');self.r[a]=ea
            elif op==14:self.r[d]=((self.r[a] if a else 0)+imm)&MASK
            elif op==37:self.write(ea,struct.pack('>I',self.r[d]),'stwu');self.r[a]=ea
            elif op==54:
                value=struct.unpack('>f',struct.pack('>I',self.ps[d][0]))[0]
                self.write(ea,struct.pack('>d',value),'stfd')
            elif op==50:
                self.ps[d][0]=bitsof(struct.unpack('>d',self.read(ea,8,'stack'))[0])
            elif op==31 and xo==467:
                spr=(w>>16&31)|(w>>11&31)<<5
                if spr!=9:raise Unsupported('non-CTR spr')
                self.ctr=self.r[d]
            elif op==11:self.eq=signed(self.r[a])==imm
            elif op==16:
                bo,bi=d,a
                if bo==12 and bi==2:take=self.eq
                elif bo==16:self.ctr=(self.ctr-1)&MASK;take=self.ctr!=0
                else:raise Unsupported(f'branch bo{bo}/bi{bi}')
                if take:nextpc=(pc+signed(w&0xfffc,16))&MASK
            elif op==21:
                sh=b;mb=w>>6&31;me=w>>1&31
                if (sh,mb,me)!=(8,0,31):raise Unsupported('rotate subset')
                self.r[a]=((self.r[d]<<8)|(self.r[d]>>24))&MASK
            elif op in (56,57):
                displacement=signed(w&0xfff,12);width=w>>15&1;gqr=w>>12&7
                if gqr:raise Unsupported('nonzero GQR selector')
                address=((self.r[a] if a else 0)+displacement)&MASK
                raw=self.read(address,4 if width else 8,'psq_lu' if op==57 else 'psq_l')
                pair=list(struct.unpack('>I' if width else '>II',raw))
                if width:pair.append(0x3f800000)
                self.ps[d]=pair
                if op==57:self.r[a]=address
            elif op==61:
                displacement=signed(w&0xfff,12);width=w>>15&1;gqr=w>>12&7
                if gqr:raise Unsupported('nonzero GQR selector')
                address=(self.r[a]+displacement)&MASK
                values=[ftz(value) for value in self.ps[d][:1 if width else 2]]
                self.write(address,struct.pack('>I' if width else '>II',*values),'psq_stu_W'+str(width));self.r[a]=address
            elif op==4:
                function=w>>1&31
                if w&1:raise Unsupported('PS Rc')
                lane=1 if function in (13,15) else 0
                avec=list(self.ps[a]);cvalue=self.ps[c][lane];bvec=list(self.ps[b]);result=[]
                if function not in (13,14,15):raise Unsupported(f'PS function{function}')
                for outlane in range(2):
                    value=mul(avec[outlane],cvalue) if function==13 else fma(avec[outlane],cvalue,bvec[outlane])
                    result.append(value)
                    self.operations.append({'case_id':self.caseid,'step':self.step,'va':hex(pc),'mnemonic':row['mnemonic'],'out_lane':outlane,'frd':d,'fra_bits':f'{avec[outlane]:08x}','frc_bits':f'{cvalue:08x}','frb_bits':f'{bvec[outlane]:08x}' if function!=13 else '', 'result_bits':f'{value:08x}'})
                self.ps[d]=result
            elif w==0x4e800020:break
            else:raise Unsupported(f'word {w:08x} at{pc:#x}')
            self.pc=nextpc
        return bytes(self.regions[2][2])

def writer(path,fields):
    f=path.open('w',newline='');w=csv.DictWriter(f,fieldnames=fields);w.writeheader();return f,w

def main():
    started=time.time();bankpath=WORK/'sa2-disc/sonicmdl.prs.decoded';bank=bankpath.read_bytes()
    packetpath=WORK/'model-data-stage/docs-prepared-v1/docs/evidence/sa2-model-payload-first-stream-sample-packets.csv'
    with packetpath.open(newline='') as f:packets=[r for r in csv.DictReader(f) if int(r['opcode'],0) in (0x23,0x29)]
    assert Counter(int(r['opcode'],0) for r in packets)=={0x23:2,0x29:69}
    matrices={
        'identity':tuple(bitsof(float(v)) for v in (1,0,0,0,1,0,0,0,1,0,0,0)),
        'signed_nonuniform':tuple(bitsof(float(v)) for v in (2,0,0,0,-.5,0,0,0,-1.5,3,-4,2)),
        'non_diagonal':tuple(bitsof(float(v)) for v in (.75,-.25,1.5,-1.25,.5,.125,.375,1,-.75,2.5,-3.25,.625)),
    }
    (OUT/'matrix-cases.json').write_text(json.dumps({name:[f'{v:08x}' for v in values] for name,values in matrices.items()},indent=2))
    cases=[]
    for ordinal,packet in enumerate(packets):
        opcode=int(packet['opcode'],0);count=int(packet['count_high16']);start=int(packet['scratch_start_low16']);offset=int(packet['data_decoded_offset'],0);stride=16 if opcode==0x23 else 24
        assert bank[int(packet['packet_decoded_offset'],0):int(packet['next_decoded_offset'],0)].hex()==packet['raw_span']
        assert count>0
        for matrix_name,matrix in matrices.items():
            cases.append({'case_id':f'real_{ordinal:03d}_{matrix_name}','source_kind':'real','source_bytes':bank,'input_offset':offset,'packet_decoded_offset':packet['packet_decoded_offset'],'opcode':opcode,'count':count,'start':start,'matrix_name':matrix_name,'matrix_bits':matrix,'record_bytes':bank[offset:offset+count*stride]})
    synthetic=[]
    for opcode in (0x23,0x29):
        stride=16 if opcode==0x23 else 24
        for name,record,matrix in (
            ('fused_cancellation',[0x3f7ffffe,0,0,0x3f7ffffe,0,0],(0x3f800001,0,0,0,0x3f800000,0,0,0,0x3f800000,0xbf800000,0,0)),
            ('signed_subnormal',[0x80000001,0x007fffff,0x00800000,0x80000001,0x007fffff,0x00800000],matrices['identity']),
            ('signed_zero',[0x80000000,0,0x80000000,0x80000000,0,0x80000000],matrices['identity']),
        ):
            words=record[:3]+[0x12345678] if opcode==0x23 else record
            data=struct.pack('>'+str(len(words))+'I',*words)+struct.pack('>'+str(stride//4)+'I',*([0x7fc12345]*(stride//4)))
            synthetic.append({'case_id':f'synthetic_{opcode:02x}_{name}','source_kind':'synthetic','source_bytes':data,'input_offset':0,'packet_decoded_offset':None,'opcode':opcode,'count':1,'start':2,'matrix_name':name,'matrix_bits':matrix,'record_bytes':data[:stride]})
    cases+=synthetic
    casefolder=OUT/'cases';casefolder.mkdir(exist_ok=False)
    handles=[]
    loadfile,loadwriter=writer(OUT/'oracle-loads.csv',['case_id','step','va','kind','region','relative_offset','size','raw_hex','unused_final_preload']);handles.append(loadfile)
    storefile,storewriter=writer(OUT/'oracle-stores.csv',['case_id','step','va','kind','scratch_offset','size','raw_hex']);handles.append(storefile)
    opfile,opwriter=writer(OUT/'oracle-ps-operations.csv',['case_id','step','va','mnemonic','out_lane','frd','fra_bits','frc_bits','frb_bits','result_bits']);handles.append(opfile)
    slotfile,slotwriter=writer(OUT/'oracle-output-slots.csv',['case_id','record_ordinal','scratch_index','before_hex','after_hex']);handles.append(slotfile)
    jsonfile=(OUT/'oracle-cases.jsonl').open('w');handles.append(jsonfile)
    combined=Counter();unknown=[];records=Counter();preload_count=0;success=0;steps=0;output_manifest=[]
    try:
        for ordinal,case in enumerate(cases):
            opcode,count,start=case['opcode'],case['count'],case['start'];stride=16 if opcode==0x23 else 24
            before=bytes((i*37+ordinal*13+0xa7)&255 for i in range((start+count+1)*32))
            machine=Machine(case['case_id'],opcode,count,start,case['source_bytes'],case['input_offset'],struct.pack('>12I',*case['matrix_bits']),before)
            try:after=machine.execute()
            except Unsupported as error:
                unknown.append({'case_id':case['case_id'],'error':str(error),'pc':hex(machine.pc),'steps':machine.step});continue
            expectedwritten=set()
            for record in range(count):
                base=(start+record)*32
                expectedwritten.update(range(base,base+12));expectedwritten.update(range(base+24,base+28) if opcode==0x23 else range(base+12,base+24))
                slotwriter.writerow({'case_id':case['case_id'],'record_ordinal':record,'scratch_index':start+record,'before_hex':before[base:base+32].hex(),'after_hex':after[base:base+32].hex()})
            assert machine.written==expectedwritten
            assert all(before[i]==after[i] for i in range(len(before)) if i not in expectedwritten)
            assert bytes(machine.regions[0][2])==struct.pack('>12I',*case['matrix_bits'])
            assert bytes(machine.regions[1][2])==case['source_bytes']
            assert bytes(machine.regions[4][2])==struct.pack('>III',0x30000000+start*32,0x20000000+case['input_offset'],count)
            inputloads=[r for r in machine.loads if r['region']=='input'];lookahead=[r for r in inputloads if r['unused_final_preload']]
            assert len(inputloads)==3*(count+1) and len(lookahead)==3
            preload_count+=len(lookahead)
            beforepath=casefolder/(case['case_id']+'.before.bin');afterpath=casefolder/(case['case_id']+'.after.bin')
            beforepath.write_bytes(before);afterpath.write_bytes(after)
            row={key:value for key,value in case.items() if key not in ('source_bytes','matrix_bits','record_bytes')}
            row.update(matrix_bits=[f'{v:08x}' for v in case['matrix_bits']],records_hex=case['record_bytes'].hex(),input_source_sha256=sha(case['source_bytes']),lookahead_hex=case['source_bytes'][case['input_offset']+count*stride:case['input_offset']+(count+1)*stride].hex(),before_file=str(beforepath.relative_to(OUT)),after_file=str(afterpath.relative_to(OUT)),before_sha256=sha(before),after_sha256=sha(after),steps=machine.step)
            jsonfile.write(json.dumps(row,separators=(',',':'))+'\n')
            loadwriter.writerows(machine.loads);storewriter.writerows(machine.stores);opwriter.writerows(machine.operations)
            combined.update(machine.coverage);steps+=machine.step;records[f'{case["source_kind"]}_{opcode:02x}']+=count;success+=1;output_manifest.append(row['after_sha256'])
    finally:
        for handle in handles:handle.close()
    reject=[]
    for label,firstword in (('nan',0x7fc00001),('infinity',0x7f800000),('overflow',0x7f7fffff)):
        data=struct.pack('>6I',firstword,0,0,0x12345678,0x7fc12345,0x7fc12345)
        matrix=list(matrices['identity'])
        if label=='overflow':matrix[0]=0x40000000
        machine=Machine('rejected_'+label,0x23,1,0,data,0,struct.pack('>12I',*matrix),bytes([0xa5])*64)
        try:machine.execute();raise AssertionError('expected unsupported '+label)
        except Unsupported as error:reject.append({'case_id':'rejected_'+label,'reason':str(error),'pc':hex(machine.pc)})
    zero=[]
    for opcode in (0x23,0x29):
        machine=Machine('zero_'+hex(opcode),opcode,0,0,bytes(4096),0,struct.pack('>12I',*matrices['identity']),bytes(8192))
        try:machine.execute(maxsteps=100);raise AssertionError('zero returned')
        except Unsupported as error:zero.append({'opcode':hex(opcode),'bounded_stop':str(error),'steps':machine.step,'CTR':hex(machine.ctr),'output_store_events':len(machine.stores),'input_load_events':sum(r['region']=='input' for r in machine.loads)})
    summary={'status':'pass' if not unknown else 'partial','success_cases':success,'real_cases':sum(c['source_kind']=='real' for c in cases),'synthetic_cases':len(synthetic),'unsupported_cases':unknown,'expected_rejections':reject,'zero_count_prefixes':zero,'records_by_kind_opcode':dict(records),'total_output_slots':sum(records.values()),'total_steps':steps,'unused_final_preload_load_events':preload_count,'word_coverage':dict(sorted(combined.items())),'distinct_executed_words':len(combined),'source_sha256':{str(bankpath):sha(bank),str(packetpath):sha(packetpath.read_bytes()),str(OUT/'parsed-original-words.csv'):sha((OUT/'parsed-original-words.csv').read_bytes())},'cache_counts':{'exact_fma_unique':fma.cache_info().currsize,'exact_mul_unique':mul.cache_info().currsize},'ordered_output_hashes_sha256':sha(''.join(output_manifest).encode()),'seconds':time.time()-started,'contract':'own original-word interpreter, not Dolphin execution; GQR0=0, RN-nearest-even, NI0/nontrapping; finite consumed inputs/intermediate results; exact rational MUL/FMA with signed zeros; PSQ final-store FTZ; disjoint memory; lookahead is loaded but not validated until consumed'}
    (OUT/'oracle-summary.ai.json').write_text(json.dumps(summary,indent=2))
    (OUT/'oracle-unsupported.json').write_text(json.dumps(unknown,indent=2))
    (OUT/'oracle.md').write_text('# Independent original-word vertex arithmetic reference\n\n'+summary['contract']+'.\n\nExecuted '+str(success)+' cases, '+str(summary['total_output_slots'])+' output slots and '+str(steps)+' original instructions. Full matrices/raw input records/copy-before and after hashes are retained per case in oracle-cases.jsonl; every output32-byte slot is retained in CSV; complete loads, stores and per-lane operations plus coverage are retained. The three declared matrix cases are explicit test inputs, not recovered live game matrices.\n\nReal cases use the 2 op23 and 69 op29 Sonic packets from the existing raw CSV and original decoded bank. All original scratch start/count fields are retained. Each test initializes independent sentinel scratch, then executes native words. Every untouched byte, source bank, matrix and descriptor remains unchanged. Both helpers perform one unused lookahead record; those loads are logged separately, and an unused nonfinite lookahead is permitted rather than incorrectly rejected.\n\nSynthetic fused cancellation, signed zero and signed subnormal cases are included for both helpers; their unused lookahead is deliberately quiet-NaN bytes. Consumed NaN/infinity and rounded overflow are explicitly rejected and retained, not silently converted. Bounded count-zero prefixes stop after 100 original instructions; neither returns. Their control-count hazard remains as described in raw-audit.md.\n\nFinite arithmetic is evaluated as exact binary rational products/sums followed by nearest-even binary32 rounding after every original multiply/FMA. Exact-zero MUL uses XOR signs; exact-zero FMA is negative only when the zero product and zero addend are both negative, otherwise nearest-even cancellation is positive zero. Underflow-to-zero uses the exact nonzero result sign. Intermediate subnormals are retained; final GQR0 float PSQ stores flush their subnormal results to signed zero. Other FPSCR/GQR states, nonfinite arithmetic, exception flags/traps, native aliases and live runtime bindings are excluded. This is an independent scratch interpreter, not actual Dolphin or game execution.\n\nAll engine/repository/original/frozen/language/helper files remain read-only. No engine implementation was copied.\n')
    (OUT/'oracle.ai.md').write_text('OwnrawPPCDA30/DAF0oracle/notDolphinexecution. ContractGQR0=0/RNnearest-even/NI0/nontrapping/finiteconsumed+results/disjointregions. ExactrationalMUL/FMAroundeach/signedzeros/finalPSQFTZ. Real71packets*3declaredmatrices+6synthetic;sentinelcopiedscratch/originalstartcount/rawpackedROL8/preserveuntouched. CompletecaseJSONL/inputraw/matrixbits/before-afterbins+hash/each32BslotCSV/load-store-PSopCSV/coverageJSON. UnusedN+1recordloadsseparate/deliberateNaNlookaheadsnotconsumed. ExpectedconsumedNaN/Inf/overflowrejected;zero-prefix100stepsnonreturn. Exactcounts/sourcehashes/unsupportedinoracle-summary.ai.json. Noengine/repo/original/frozenchanges.\n')
    print(json.dumps({key:summary[key] for key in ('status','success_cases','real_cases','synthetic_cases','records_by_kind_opcode','total_output_slots','total_steps','unused_final_preload_load_events','distinct_executed_words','cache_counts','seconds')}))
    if unknown:print('First unsupported',json.dumps(unknown[0]))

if __name__=='__main__':main()
