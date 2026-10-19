from pathlib import Path
import csv,hashlib,importlib.util,json,struct,time
from collections import Counter

OUT=Path(__file__).resolve().parent;WORK=OUT.parent
spec=importlib.util.spec_from_file_location('own_vertex_oracle',WORK/'sa2-model-transform-v1/vertex_oracle_v1.py')
own=importlib.util.module_from_spec(spec);spec.loader.exec_module(own)
MASK=0xffffffff;sha=lambda b:hashlib.sha256(b).hexdigest()
with (OUT/'original-words.csv').open(newline='') as f:WORDS={int(r['va'],0):r for r in csv.DictReader(f) if int(r['owner'],0)==0x8011dc98}
Unsupported=own.Unsupported

class Machine(own.Machine):
    def __init__(self,caseid,count,start,mode,input_bytes,input_offset,matrix_bytes,before):
        super().__init__(caseid,0x29,count,start,input_bytes,input_offset,matrix_bytes,before)
        self.pc=0x8011dc98;self.stride=28;self.r[5]=mode;self.gqr1=0xdeadbeef
    def execute(self,maxsteps=200000):
        while True:
            if self.step>=maxsteps:raise Unsupported('bounded instruction limit')
            row=WORDS.get(self.pc)
            if row is None:raise Unsupported(f'unknown PC {self.pc:#x}')
            w=int(row['word'],16);pc=self.pc;nextpc=(pc+4)&MASK;self.step+=1;self.coverage[hex(pc)]+=1
            op,d,a,b,c=w>>26,w>>21&31,w>>16&31,w>>11&31,w>>6&31;xo=w>>1&1023
            imm=own.signed(w&0xffff,16);ea=((self.r[a] if a else 0)+imm)&MASK
            if op==32:self.r[d]=int.from_bytes(self.read(ea,4,'lwz'),'big')
            elif op==41:self.r[d]=int.from_bytes(self.read(ea,2,'destination_lhzu'),'big');self.r[a]=ea
            elif op==14:self.r[d]=((self.r[a] if a else 0)+imm)&MASK
            elif op==25:self.r[a]=(self.r[d]|((w&0xffff)<<16))&MASK
            elif op==37:self.write(ea,struct.pack('>I',self.r[d]),'stwu');self.r[a]=ea
            elif op==54:self.write(ea,struct.pack('>d',struct.unpack('>f',struct.pack('>I',self.ps[d][0]))[0]),'stfd')
            elif op==50:self.ps[d][0]=own.bitsof(struct.unpack('>d',self.read(ea,8,'stack'))[0])
            elif op==31 and xo==467:
                spr=(w>>16&31)|(w>>11&31)<<5
                if spr==9:self.ctr=self.r[d]
                elif spr==913:self.gqr1=self.r[d]
                else:raise Unsupported(f'unknown SPR {spr}')
            elif op==31 and xo==266:self.r[d]=(self.r[a]+self.r[b])&MASK
            elif op==31 and xo==444:self.r[a]=self.r[d]|self.r[b]
            elif op==11:self.eq=own.signed(self.r[a])==imm
            elif op==16:
                if (d,a)==(12,2):take=self.eq
                elif (d,a)==(4,2):take=not self.eq
                elif d==16:self.ctr=(self.ctr-1)&MASK;take=self.ctr!=0
                else:raise Unsupported(f'branch BO/BI {d}/{a}')
                if take:nextpc=(pc+own.signed(w&0xfffc,16))&MASK
            elif op==18:nextpc=(pc+own.signed(w&0x3fffffc,26))&MASK
            elif op==21:
                sh=b;mb=w>>6&31;me=w>>1&31
                if (sh,mb,me)!=(5,0,26):raise Unsupported('rotate-mask subset')
                self.r[a]=(self.r[d]<<5)&0xffffffe0
            elif op in (56,57):
                displacement=own.signed(w&0xfff,12);W=w>>15&1;I=w>>12&7;address=((self.r[a] if a else 0)+displacement)&MASK
                if I==0:
                    raw=self.read(address,4 if W else 8,'psq_lu_GQR0' if op==57 else 'psq_l_GQR0')
                    pair=list(struct.unpack('>I' if W else '>II',raw))
                elif I==1 and W and self.gqr1==0x08070807:
                    raw=self.read(address,2,'weight_GQR1');pair=[own.bitsof(int.from_bytes(raw,'big',signed=True)/256)]
                else:raise Unsupported(f'PSQ load GQR{I}/W{W}/{self.gqr1:#x}')
                if W:pair.append(0x3f800000)
                self.ps[d]=pair
                if op==57:self.r[a]=address
            elif op==60:
                displacement=own.signed(w&0xfff,12);W=w>>15&1;I=w>>12&7
                if I:raise Unsupported('store nonzero GQR')
                address=((self.r[a] if a else 0)+displacement)&MASK
                values=[own.ftz(v) for v in self.ps[d][:1 if W else 2]]
                self.write(address,struct.pack('>I' if W else '>II',*values),'psq_st_W'+str(W))
            elif op==4:
                function=w>>1&31;lane=1 if function in (13,15) else 0
                if function not in (12,13,14,15) or w&1:raise Unsupported(f'PS op/Rc {function}/{w&1}')
                avec=list(self.ps[a]);cv=self.ps[c][lane];bvec=list(self.ps[b]);result=[]
                for laneout in range(2):
                    val=own.mul(avec[laneout],cv) if function in (12,13) else own.fma(avec[laneout],cv,bvec[laneout])
                    result.append(val)
                    self.operations.append({'case_id':self.caseid,'step':self.step,'va':hex(pc),'mnemonic':row['mnemonic'],'out_lane':laneout,'frd':d,'fra_bits':f'{avec[laneout]:08x}','frc_bits':f'{cv:08x}','frb_bits':f'{bvec[laneout]:08x}' if function in (14,15) else '','result_bits':f'{val:08x}'})
                self.ps[d]=result
            elif w==0x4e800020:break
            else:raise Unsupported(f'word {w:08x} at{pc:#x}')
            self.pc=nextpc
        return bytes(self.regions[2][2])

def sentinel(slots,overrides=None):
    data=bytearray(slots*32)
    for slot in range(slots):
        vals=[(-1 if (slot+component)&1 else 1)*(slot*3+component+1)/8 for component in range(6)]
        struct.pack_into('>6f',data,slot*32,*vals)
        data[slot*32+24:slot*32+32]=bytes((slot*37+k*19+0xa7)&255 for k in range(8))
    for slot,words in (overrides or {}).items():struct.pack_into('>6I',data,slot*32,*words)
    return bytes(data)

def record(words,weight,dest):return struct.pack('>6IhH',*words,weight,dest)

def main():
    started=time.time();bankpath=WORK/'sa2-disc/sonicmdl.prs.decoded';bank=bankpath.read_bytes()
    packetpath=WORK/'sa2-weighted-samples-v1/weighted-packets.ai.json';packets=json.loads(packetpath.read_text())['packets'];assert len(packets)==83
    matrices={k:tuple(int(v,16) for v in values) for k,values in json.loads((WORK/'sa2-model-transform-v1/matrix-cases.json').read_text()).items()}
    (OUT/'matrix-cases.json').write_text(json.dumps({k:[f'{v:08x}' for v in vs] for k,vs in matrices.items()},indent=2))
    cases=[]
    for index,packet in enumerate(packets):
        offset=int(packet['data_offset'],0);count=packet['count'];start=packet['first_scratch_raw_u16'];mode=packet['masked_variant_7bits']
        assert bank[int(packet['packet_offset'],0):int(packet['declared_end_exclusive'],0)].hex()==packet['raw_packet_bytes']
        raw=bank[offset:offset+count*28];dests=[]
        for n,r in enumerate(packet['records']):
            assert raw[n*28:n*28+28].hex()==r['raw_record'];dests.append(struct.unpack_from('>H',raw,n*28+26)[0])
        for matrixname,matrix in matrices.items():cases.append({'case_id':f'real_{index:03d}_{matrixname}','kind':'real','source':bank,'input_offset':offset,'packet_offset':packet['packet_offset'],'count':count,'start':start,'variant':mode,'matrix_name':matrixname,'matrix_bits':matrix,'records':raw,'destinations':dests,'before_overrides':{}})
    identity=matrices['identity'];words=tuple(own.bitsof(v) for v in (-1.25,.5,2.,.25,-.75,1.5));lookahead=struct.pack('>6IhH',*([0x7fc12345]*6),-123,65535)
    def add(name,mode,rows,matrix=identity,start=2,overrides=None,extra=lookahead):
        data=b''.join(rows);dests=[struct.unpack_from('>H',r,26)[0] for r in rows]
        cases.append({'case_id':'synthetic_'+name,'kind':'synthetic','source':data+extra,'input_offset':0,'packet_offset':None,'count':len(rows),'start':start,'variant':mode,'matrix_name':name,'matrix_bits':tuple(matrix),'records':data,'destinations':dests,'before_overrides':overrides or {}})
    for mode in (0,1,2,127):
        for weight in (-32768,-257,-256,-1,0,1,127,128,255,256,257,32767):
            add(f'mode{mode}_weight{weight}',mode,[record(words,weight,5)])
    for mode in (0,2):
        for start,dest in ((0,0),(2,65535),(65535,65535)):add(f'base{start}_dest{dest}_mode{mode}',mode,[record(words,128,dest)],start=start)
    for mode in (0,1,2):
        for reverse in (False,True):
            xs=[2**24,1.,-(2**24)]
            if reverse:xs.reverse()
            rows=[record(tuple(own.bitsof(v) for v in (x,0,0,0,0,0)),256,3) for x in xs]
            add(f'ordered_mode{mode}_reverse{int(reverse)}',mode,rows,overrides={5:[0]*6})
    qbits=own.bitsof(255/256);rounded=own.mul(0x3f800001,qbits)
    add('accum_fused_weight',2,[record((0x3f800001,0,0,0,0,0),255,1)],overrides={3:[rounded^0x80000000,0,0,0,0,0]})
    add('zero_weight_FTZ_and_zero_sign',1,[record(tuple(own.bitsof(float(v)) for v in (1,2,3,4,5,6)),0,1)],overrides={3:[1,0x80000001,0x80000000,0x007fffff,0x807fffff,0]})
    add('overwrite_ignores_old_nonfinite',0,[record(words,128,1)],overrides={3:[0x7fc00001,0x7f800000,0xff800000,0x7f800001,0xffc12345,0]})
    special=(0x3f800001,0,0,0,0x3f800000,0,0,0,0x3f800000,0xbf800000,0,0)
    add('transform_fused_before_weight',0,[record((0x3f7ffffe,0,0,0,0,0),128,1)],matrix=special)
    add('nonzero_count1_only24lookahead',1,[record(words,128,1)],extra=lookahead[:24])
    folder=OUT/'cases';folder.mkdir(exist_ok=False)
    files=[]
    def csvout(name,fields):
        f=(OUT/name).open('w',newline='');files.append(f);w=csv.DictWriter(f,fieldnames=fields);w.writeheader();return w
    loadwriter=csvout('oracle-loads.csv',['case_id','step','va','kind','region','relative_offset','size','raw_hex','unused_final_preload'])
    storewriter=csvout('oracle-stores.csv',['case_id','step','va','kind','scratch_offset','size','raw_hex'])
    opwriter=csvout('oracle-PS-operations.csv',['case_id','step','va','mnemonic','out_lane','frd','fra_bits','frc_bits','frb_bits','result_bits'])
    slotwriter=csvout('oracle-output-slots.csv',['case_id','record_ordinal','destination_raw','scratch_index','before_hex','after_hex'])
    jf=(OUT/'oracle-cases.jsonl').open('w');files.append(jf)
    coverage=Counter();unknown=[];counts=Counter();steps=0;outputhashes=[];loads_by_mode=Counter()
    try:
        for case in cases:
            cid=case['case_id'];start,count,mode=case['start'],case['count'],case['variant'];highest=start+max(case['destinations'])
            before=sentinel(highest+2,case['before_overrides']);matrixbytes=struct.pack('>12I',*case['matrix_bits'])
            machine=Machine(cid,count,start,mode,case['source'],case['input_offset'],matrixbytes,before)
            try:after=machine.execute()
            except Unsupported as error:unknown.append({'case_id':cid,'pc':hex(machine.pc),'reason':str(error),'steps':machine.step});continue
            expectedwritten={offset for dest in case['destinations'] for offset in range((start+dest)*32,(start+dest)*32+24)}
            assert machine.written==expectedwritten and all(before[i]==after[i] for i in range(len(before)) if i not in expectedwritten)
            assert bytes(machine.regions[0][2])==matrixbytes and bytes(machine.regions[1][2])==case['source']
            assert bytes(machine.regions[4][2])==struct.pack('>III',0x30000000+start*32,0x20000000+case['input_offset'],count)
            assert machine.gqr1==0x08070807
            inputloads=[r for r in machine.loads if r['region']=='input'];oldloads=[r for r in machine.loads if r['region']=='scratch'];extra=[r for r in inputloads if r['unused_final_preload']]
            expectedextra=3 if mode and count==1 else 5
            assert len(inputloads)==5*count+expectedextra and len(extra)==expectedextra
            assert len(oldloads)==(4*count if mode else 0)
            loads_by_mode[f'variant{mode}_count1' if count==1 else f'variant{mode}_multi']+=len(extra)
            beforepath=folder/(cid+'.before.bin');afterpath=folder/(cid+'.after.bin');beforepath.write_bytes(before);afterpath.write_bytes(after)
            targets=sorted(set(start+d for d in case['destinations']))
            for n,dest in enumerate(case['destinations']):
                index=start+dest;lo=index*32
                slotwriter.writerow({'case_id':cid,'record_ordinal':n,'destination_raw':dest,'scratch_index':index,'before_hex':before[lo:lo+32].hex(),'after_hex':after[lo:lo+32].hex()})
            row={k:v for k,v in case.items() if k not in ('source','records','matrix_bits','before_overrides')}
            row.update(matrix_bits=[f'{v:08x}' for v in case['matrix_bits']],records_hex=case['records'].hex(),lookahead_hex=case['source'][case['input_offset']+28*count:case['input_offset']+28*(count+1)].hex(),input_source_sha256=sha(case['source']),before_file=str(beforepath.relative_to(OUT)),after_file=str(afterpath.relative_to(OUT)),before_sha256=sha(before),after_sha256=sha(after),target_min=min(targets),target_max=max(targets),unique_targets=len(targets),gqr1_before='deadbeef',gqr1_after='08070807',steps=machine.step)
            jf.write(json.dumps(row,separators=(',',':'))+'\n');loadwriter.writerows(machine.loads);storewriter.writerows(machine.stores);opwriter.writerows(machine.operations)
            coverage.update(machine.coverage);counts[case['kind']]+=1;counts[case['kind']+'_records']+=count;steps+=machine.step;outputhashes.append(row['after_sha256'])
    finally:
        for f in files:f.close()
    zero=[]
    for mode in (0,2):
        data=b''.join(record((0,)*6,0,0) for _ in range(50));machine=Machine('zero',0,0,mode,data,0,struct.pack('>12I',*identity),sentinel(2))
        try:machine.execute(maxsteps=200);raise AssertionError('zero unexpectedly returned')
        except Unsupported as error:zero.append({'variant':mode,'reason':str(error),'steps':machine.step,'CTR':hex(machine.ctr),'stores':len(machine.stores),'gqr1_after':hex(machine.gqr1)})
    summary={'status':'pass' if not unknown else 'partial','cases':dict(counts),'unknown':unknown,'steps':steps,'distinct_helper_words_executed':len(coverage),'coverage':dict(sorted(coverage.items())),'lookahead_load_events_by_variant_count':dict(loads_by_mode),'zero_count_bounded_prefixes':zero,'ordered_output_hashes_sha256':sha(''.join(outputhashes).encode()),'seconds':time.time()-started,'source_hashes':{str(bankpath):sha(bank),str(packetpath):sha(packetpath.read_bytes()),str(WORK/'sa2-model-transform-v1/vertex_oracle_v1.py'):sha((WORK/'sa2-model-transform-v1/vertex_oracle_v1.py').read_bytes())},'contract':'Own original-word interpreter, not Dolphin/game execution; GQR0=0, original GQR1 write08070807, RNnearest/NI0/nontrapping, finite consumed PS arithmetic/all lanes, disjoint buffers; exact rational MUL/FMA with original order, signed zeros, final PSQ-store FTZ'}
    (OUT/'oracle-summary.ai.json').write_text(json.dumps(summary,indent=2));(OUT/'oracle-unknown.json').write_text(json.dumps(unknown,indent=2))
    (OUT/'oracle.md').write_text('# Independent weighted original-word oracle\n\n'+summary['contract']+'.\n\nAll 83 real packets retain original count, scratch base, variant, relative destination and record order. Each of three explicitly declared matrices runs with fresh finite six-word-per-slot sentinel scratch and arbitrary last-eight-byte sentinels. These isolated packet cases do not imply cross-packet runtime ordering or matrix bindings. Every original opcode is decoded at execution; no engine formula is imported. Primary arithmetic is exact rational nearest-even binary32 after each MUL/FMA; PSQ weight type7/scale8 is exact s16/256; final PSQ float stores flush subnormals to signed zero.\n\nComplete inputs/matrix words/record bytes/before-after binary paths/hashes/target domains/GQR1 state are in oracle-cases.jsonl. All load/store/order events and per-lane arithmetic rows are complete CSV; every referenced destination32-byte slot is retained. Repeated-destination rows point to the final slot image; actual intermediate writes and old-value reads remain in event CSV. Every unwritten byte, source buffer, matrix and descriptor is checked unchanged. GQR1 changes from DEADBEEF to08070807 on every successful helper invocation.\n\nSynthetic coverage includes all four test variants0/1/2/127, signed16 weight endpoints/negative/zero/255/256/257, additive base+dest0/65535, ordered/reversed duplicate destinations, fused weighted accumulation cancellation, transform-before-weight fusion, zero-weight FTZ/signed-zero feedback, mode0 ignoring nonfinite old scratch, and the special nonzero count1 lookahead of only24bytes. Original N0 is bounded to200steps and does not return. Exact totals/coverage/source hashes are in JSON.\n\nFinite/all-lane arithmetic is a conservative oracle subset: it rejects nonfinite consumed values or overflowing paired results, including discarded PS lanes. Native invalid exceptions/FPSCR flags, nonzero live GQR0, alternative rounding/NI, original memory aliases, native faults, and full runtime binding/order remain outside this reference. No repository/engine/native/frozen/language/helper changes.\n')
    (OUT/'oracle.ai.md').write_text('OwnDC98raw160wordoracle/notDolphinexecution. GQR0=0/GQR1native08070807/RNnearest/NI0/nontrapping/finiteallconsumedlanes/disjointregions. ExactrationalMUL/FMA/signedzero/storeFTZ. Real83*3declaredmatrices/originalcount-base-variant-recordorder/finite6wordssentinel+arbitrarylast8;noexecutionbindinginference. Syntheticmodes0/1/2/127;S16weightsedges;destbase+0/65535;duplicatesorder;fusedaccum;zeroweightFTZ;mode0oldNaNignored;mode1N1only24lookahead;N0bounded200nonreturn. CompletecaseJSONL/beforeafterbins+hashes/load-store-PSCSV/finalslots/GQRstate/coverageJSON. Noenginecopy/repoedits.\n')
    print(json.dumps({k:summary[k] for k in ('status','cases','steps','distinct_helper_words_executed','lookahead_load_events_by_variant_count','zero_count_bounded_prefixes','seconds')}))
    if unknown:print('First unknown',json.dumps(unknown[0]))

if __name__=='__main__':main()
