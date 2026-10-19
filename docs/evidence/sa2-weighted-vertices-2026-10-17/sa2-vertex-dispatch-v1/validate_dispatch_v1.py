"""Once-only bounded original dispatcher integer model; numerical helpers remain opaque hooks."""
import collections,csv,hashlib,json,struct
from pathlib import Path
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
assert not (OUT/'validation.ai.json').exists()
def rows(path):
    with Path(path).open(newline='',encoding='utf-8-sig') as f:return list(csv.DictReader(f))
def save(name,values):
    keys=list(dict.fromkeys(k for r in values for k in r)) or ['result']
    with (OUT/name).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,keys);w.writeheader();w.writerows(values)
def s(v,b=16):return v-(1<<b) if v&(1<<(b-1)) else v
def mask(mb,me):return sum(1<<(31-i) for i in range(32) if (mb<=i<=me if mb<=me else i>=mb or i<=me))
def rot(v,n):return ((v<<n)|(v>>((32-n)%32)))&0xffffffff
source=rows(OUT/'original-words.csv');code={int(r['va'],16):int(r['word'],16) for r in source}
helpers={0x23:0x8011da30,0x29:0x8011daf0,0x2c:0x8011dc98,0x2a:0x8011dc10}
R13=0x400000;STATE=(R13-0x7178)&0xffffffff;BINDING=(R13-0x71fc)&0xffffffff;STACK=0x200000;BASE=0x100000;SCRATCH=0x600000

def execute(data,initial_state=0x12345678,initial_gqr1=0xdeadbeef,change_binding=False):
    mem={BASE+i:b for i,b in enumerate(data)};events=[];calls=[];regs=[0]*32;cr=[False]*4
    regs[1],regs[3],regs[4],regs[13]=STACK,BASE,SCRATCH,R13
    gqr1=initial_gqr1
    def put(addr,value):
        for i,b in enumerate(struct.pack('>I',value&0xffffffff)):mem[addr+i]=b
    def get(addr):
        assert all(addr+i in mem for i in range(4)),('host control-model bounds',hex(addr))
        return int.from_bytes(bytes(mem[addr+i] for i in range(4)),'big')
    put(STATE,initial_state);put(BINDING,0x800000)
    pc=0x8011d1ec;steps=0;stop=''
    while pc!=0x8011d2d8:
        assert steps<100000,'host instruction budget'
        steps+=1;w=code[pc];op=w>>26;d=(w>>21)&31;a=(w>>16)&31;b=(w>>11)&31;xo=(w>>1)&1023;imm=s(w&65535);next_pc=pc+4
        if op==32:
            addr=((regs[a] if a else 0)+imm)&0xffffffff;regs[d]=get(addr)
            events.append({'kind':'read32','site':hex(pc),'address':hex(addr),'value':hex(regs[d])})
        elif op==36:
            addr=((regs[a] if a else 0)+imm)&0xffffffff;put(addr,regs[d]);events.append({'kind':'write32','site':hex(pc),'address':hex(addr),'value':hex(regs[d])})
        elif op==14:regs[d]=((regs[a] if a else 0)+imm)&0xffffffff
        elif op==21:regs[a]=rot(regs[d],b)&mask((w>>6)&31,(w>>1)&31)
        elif op==24:regs[a]=regs[d]|(w&65535)
        elif op in [10,11]:
            lhs=regs[a] if op==10 else s(regs[a],32);rhs=w&65535 if op==10 else imm;cr=[lhs<rhs,lhs>rhs,lhs==rhs,False]
        elif op==31 and xo==444:regs[a]=regs[d]|regs[b]
        elif op==31 and xo==266:regs[d]=(regs[a]+regs[b])&0xffffffff
        elif op==16:
            assert d in [4,12]
            if cr[a]==bool(d&8):next_pc=(pc+s(w&0xfffc))&0xffffffff
        elif op==18:
            target=(s(w&0x3fffffc,26)+(0 if w&2 else pc))&0xffffffff
            if w&1:
                assert target in helpers.values()
                descriptor=regs[3];call={'site':hex(pc),'target':hex(target),'descriptor':hex(descriptor),'destination':hex(get(descriptor)),'source':hex(get(descriptor+4)),'count':get(descriptor+8),'matrix_pointer':hex(regs[4]),'r5_at_call':hex(regs[5]),'state_before_call':hex(get(STATE)),'GQR1_before_call':hex(gqr1)}
                calls.append(call);events.append({'kind':'helper_call_known_control_only',**call})
                if target==0x8011dc10:stop='unknown2A call reached after known pre-call effects; math not modeled';break
                if target==0x8011dc98:gqr1=0x08070807
                if change_binding:put(BINDING,get(BINDING)+0x100)
            else:next_pc=target
        else:raise AssertionError(('unsupported dispatcher instruction',hex(pc),hex(w)))
        pc=next_pc
    return {'return_r3':regs[3] if not stop else None,'state':get(STATE),'GQR1':gqr1,'binding':get(BINDING),'calls':calls,'events':events,'steps':steps,'stop':stop or 'normal literal0 return'},mem

def packet(op,upper=None,info=0x00010007,mode=0,flag15=0):
    stride={0x23:16,0x29:24,0x2c:28}.get(op,0)
    if upper is None:upper=(8+stride)//4-1
    header=(upper<<16)|(flag15<<15)|(mode<<8)|op
    size=4*(upper+1)
    data=struct.pack('>II',header,info)
    if size>=8:data+=bytes(size-8)
    return data

opcode_rows=[]
for op in range(256):
    data=(struct.pack('>I',0xabcd00ff) if op==255 else packet(op)+struct.pack('>I',255))
    result,_=execute(data)
    expected=helpers.get(op)
    assert [int(c['target'],16) for c in result['calls']]==([expected] if expected else [])
    expected_state=0x12345678|(3 if op==0x23 else 2 if op==0x2a else 0)
    assert result['state']==expected_state
    assert result['GQR1']==(0x08070807 if op==0x2c else 0xdeadbeef)
    if op!=0x2a:assert result['return_r3']==0
    opcode_rows.append({'opcode':hex(op),'helper':hex(expected) if expected else '', 'state_after_known_effects':hex(result['state']),'GQR1_after_modeled_known_effects':hex(result['GQR1']),'stop':result['stop'],'return_r3':result['return_r3'],'original_integer_steps':result['steps']})
upper_rows=[]
for upper in [0,1,2,3,0x7fff,0x8000,0xfffe,0xffff]:
    for address in [0,1,0x7ffffffc,0x80000000,0xfffffff8,0xfffffffc]:
        direct=(address+4*(upper+1))&0xffffffff
        native=(address+8+((rot((upper-1)&0xffffffff,2))&mask(0,29)))&0xffffffff
        assert direct==native
        upper_rows.append({'header_upper16':hex(upper),'packet_address':hex(address),'encoded_bytes':4*(upper+1),'native_next_mod32':hex(native),'minimum_nonEND_info_read_bytes':8,'info_overlaps_next_header':upper==0})
info_rows=[]
for n in range(65536):
    info=(n<<16)|(65535-n)
    assert (rot(info&0xffff0000,16)&65535)==n
    assert (rot(info&65535,5)&0xffffffe0)==(65535-n)*32
    info_rows.append({'info_raw':hex(info),'count':n,'base_index':65535-n,'base_byte_offset':(65535-n)*32})
mode_rows=[]
for mode in range(128):
    for flag in [0,1]:
        header=0xffff0000|(flag<<15)|(mode<<8)|0x2c
        raw=rot(header&65535,0)&mask(17,15)
        actual=rot(raw,24)&255
        assert actual==mode==((header&0x7fff)>>8)
        mode_rows.append({'header':hex(header),'mode':mode,'ignored_bit15':flag,'callee_r5':actual})
state_rows=[]
for low in range(65536):
    for high in [0,0xffff,0xaaaa,0x5555]:
        state=(high<<16)|low
        for added in [2,3]:assert ((state|added)>>16)==high
        state_rows.append({'initial':hex(state),'after_OR2':hex(state|2),'after_OR3':hex(state|3),'upper16_unchanged':True})
trace_rows=[];trace_cases=[]
sequences={'mixed':[0x29,0x10,0x23,0x29,0x2c,0x23,0x2c],'opaque_only':[0x10],'unknown2A':[0x2a],'per_call_reload_outside_closed_contract':[0x29,0x23,0x2c]}
for name,ops in sequences.items():
    data=b''.join(packet(op,mode=0x7f if op==0x2c else 0) for op in ops)+struct.pack('>I',255)
    r,_=execute(data,change_binding=name=='per_call_reload_outside_closed_contract')
    trace_rows.extend({'case':name,'event':i,**event} for i,event in enumerate(r['events']))
    trace_cases.append({'case':name,'ops':';'.join(hex(op) for op in ops),'state':hex(r['state']),'GQR1':hex(r['GQR1']),'matrix_arguments':';'.join(c['matrix_pointer'] for c in r['calls']),'steps':r['steps'],'stop':r['stop'],'qualification':'synthetic explicit bindings/opaque helper hooks; no numerical or native execution'})
    if name=='per_call_reload_outside_closed_contract':assert [c['matrix_pointer'] for c in r['calls']]==['0x800000','0x800100','0x800200']
overlap=[]
for op in [0,0x10,0xfe]:
    r,_=execute(struct.pack('>II',op,0xabcd00ff))
    reads=[e for e in r['events'] if e['kind']=='read32' and e['address']==hex(BASE+4)]
    assert len(reads)==2 and not r['calls'] and r['return_r3']==0
    overlap.append({'opcode':hex(op),'header_upper16':0,'encoded_bytes':4,'information_raw':'0xabcd00ff','next_header_same_word':True,'reads_of_overlap_word':len(reads),'state_unchanged':True,'GQR1_unchanged':True})

# Closed helper proof is a static footprint under explicit nonalias and no asynchronous mutation.
footprints=[]
for entry in [0x8011da30,0x8011daf0,0x8011dc98]:
    values=[r for r in source if int(r['entry'],16)==entry]
    transfers=[r for r in values if int(r['opcode']) in [18,19]]
    assert all(int(r['opcode'])==19 and int(r['word'],16)==0x4e800020 or int(r['opcode'])==18 and not int(r['word'],16)&1 for r in transfers)
    writes13=[r for r in values if '13' in r['GPR_writes_decoded'].split(';') or int(r['opcode']) in [57,61] and int(r['a'])==13]
    assert not writes13
    stores=[r for r in values if int(r['opcode']) in [36,37,38,39,44,45,47,52,53,54,55,60,61]]
    assert not any(int(r['a'])==13 for r in stores)
    spr=[r for r in values if int(r['opcode'])==31 and int(r['xo']) in [339,467] and not int(r['word'],16)&1 and (((int(r['word'],16)>>16)&31)|(((int(r['word'],16)>>11)&31)<<5))==913]
    assert len(spr)==(1 if entry==0x8011dc98 else 0)
    footprints.append({'helper':hex(entry),'words':len(values),'direct_or_indirect_calls':0,'GPR13_writes':0,'Dform_stores_with_RA13':0,'store_base_registers':';'.join(map(str,sorted({int(r['a']) for r in stores}))), 'GQR1_writes':len(spr),'matrix_binding_preservation':'conditional on no scratch/stack/source/descriptor/global/matrix overlap and no external mutation; not runtime proof'})
save('all-256-opcodes.csv',opcode_rows);save('upper16-advance-boundaries.csv',upper_rows);save('information-extraction-domain.csv',info_rows);save('mode-extraction-domain.csv',mode_rows);save('state-OR-domain.csv',state_rows);save('control-trace-events.csv',trace_rows);save('control-trace-cases.csv',trace_cases);save('opaque-4byte-overlap-cases.csv',overlap);save('closed-helper-footprints.csv',footprints)
for r in rows(OUT/'input-sha256.csv'):assert hashlib.sha256(Path(r['path']).read_bytes()).hexdigest()==r['sha256']
result={'result':'passed','opcode_cases':len(opcode_rows),'advance_boundary_cases':len(upper_rows),'information_cases':len(info_rows),'mode_cases':len(mode_rows),'state_OR_cases':len(state_rows),'trace_cases':len(trace_cases),'trace_events':len(trace_rows),'unknown_overlap_cases':len(overlap),'closed_helpers':footprints,'2A':'only call/precall control traced; unknown math never executed/emulated','normal_return':0,'matrix_read_sites':['8011D248','8011D260','8011D288','8011D2AC'],'matrix_binding':'freshreadperrecognizedcall;constant onlyunderdeclaredclosed/nonalias/noexternalmutation','native_execution':False,'project_opens':0,'engine_changes':[]}
(OUT/'validation.ai.json').write_text(json.dumps(result,indent=2)+'\n');(OUT/'validation.md').write_text('# Dispatcher integer/control validation\n\nOnce-only original-word model checked all256 opcodes, upper16/address-wrap boundaries, full16-bit information extraction, allmode/bit15 cases, complete low16 state-OR domain across four upper patterns, ordered call/state/matrix traces and unknown four-byte info/header overlap. Numerical helpers are opaque control hooks, with2A stopped at its unresolved call. Closed-helper matrix preservation requires explicit nonalias/noexternalmutation. Complete CSV and AI twin preserve all results.\n')
print(json.dumps(result,separators=(',',':')))
