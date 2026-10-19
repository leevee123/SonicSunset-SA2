"""Finalize source-guarded bounded vertex dispatcher contract and typed footprint proof."""
import csv,hashlib,json
from pathlib import Path
OUT=Path(__file__).resolve().parent
assert not (OUT/'dispatch-reference.ai.json').exists()
def sha(b):return hashlib.sha256(b).hexdigest()
def rows(p):
    with Path(p).open(newline='',encoding='utf-8-sig') as f:return list(csv.DictReader(f))
def save(name,values):
    keys=list(dict.fromkeys(k for r in values for k in r)) or ['result']
    with (OUT/name).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,keys);w.writeheader();w.writerows(values)
inspection=json.loads((OUT/'inspection.ai.json').read_text());validation=json.loads((OUT/'validation.ai.json').read_text())
inputs=rows(OUT/'input-sha256.csv')
for r in inputs:assert sha(Path(r['path']).read_bytes())==r['sha256'],r['path']
native=rows(OUT/'original-words.csv');byva={int(r['va'],16):r for r in native};typed=[]
for r in native:
    if r['entry'] not in ['0x8011da30','0x8011daf0','0x8011dc98']:continue
    w=int(r['word'],16);op=w>>26;d=(w>>21)&31;a=(w>>16)&31;xo=(w>>1)&1023;writes=[]
    if op in [14,15,32,33,34,35,40,41,42,43]:writes=[d]+([a] if op in [33,35,41,43] else [])
    elif op in [20,21,24,25,26,27,28,29]:writes=[a]
    elif op in [37,39,45,53,55,57,61]:writes=[a]
    elif op==31:
        assert xo in [266,444,467]
        writes=[d] if xo==266 else [a] if xo==444 else []
    elif op==4:
        assert (w>>1)&63 not in [6,7,38,39],('Unexpected indexed quantized memory form',r['va'])
    else:assert op in [16,18,19,36,38,44,48,50,52,54,56,60]
    assert 13 not in writes
    typed.append({**r,'typed_GPR_writes':';'.join(map(str,writes)),'GPR13_preserved':True,'effect_scope':'GPR/SPR/control only;FP effects separately audited'})
save('typed-helper-GPR-effect-coverage.csv',typed)
assert len(typed)==48+72+160
for c in rows(OUT/'direct-call-references.csv'):
    assert int(c['target'],16)==int(c['native_target'],16)
site_values={0x8011d20c:'Every nonEND information-word read',0x8011d220:'Descriptor count atsp+18',0x8011d224:'Descriptor source atsp+14',0x8011d234:'Descriptor destination atsp+10',0x8011d248:'29matrix pointer read',0x8011d24c:'29helper call',0x8011d260:'2Cmatrix pointer read',0x8011d264:'2Cmasked mode extraction',0x8011d268:'2Chelper call',0x8011d280:'2AprecallstateOR2store',0x8011d288:'2Amatrix pointer read',0x8011d28c:'2Aunknownmathcall',0x8011d2a4:'23precallstateOR3store',0x8011d2ac:'23matrix pointer read',0x8011d2b0:'23helper call',0x8011d2b4:'Encoded headerupper16minus1',0x8011d2b8:'Encodedskipunits*4mod32',0x8011d2bc:'Next cursor',0x8011d2c0:'Header read',0x8011d2cc:'LowopcodeFF test BEFOREinfo',0x8011d2d4:'Literal0 return register'}
sites=[{**byva[a],'effect':effect} for a,effect in site_values.items()];save('key-original-sites.csv',sites)
site_table='\n'.join(f"| {r['va']} | {r['dol_offset']} | {r['iso_offset']} | {r['word']} | {r['effect']} |" for r in sites)
human=f'''# Original first-stream dispatcher8011D1D4

The dispatcher supports an additive CPU stream path with explicit initial state,GQR1 and matrix under declared nonalias/finite numerical rules. Exact packet stepping, calls and state effects are established; op2A's math remains unsupported. No live SDA/matrix/FP binding, gameplay drawing or complete game behavior is inferred.

## Source and original coordinates

Both frozen generated C views were read first. The dispatcher is72 original words at8011D1D4/DOL11A1D4/ISO1388D4, ending just before8011D2F4. It was completed C-only and has no individual ASM export; complete original words are selected by matching both-view body ranges and DOL/ISO bytes. All17 source artifacts,386 selected words across dispatcher/23/29/2C and boundary-only2A scopes,632 retained ASM rows and14 graph-reference rows are preserved with source hashes. Scopes overlap prior audits and do not increase whole-corpus decompilation totals.

| Original VA | DOL offset | ISO offset | Original word | Established effect |
|---|---|---|---|---|
{site_table}

## Read order, descriptor and packet advancement

Incoming r3 is the stream pointer and r4 the scratch base, saved into r30/r31. AtD2C0 the dispatcher reads a BEu32 header and advances four bytes. Its low8 bits are compared withFF atD2CC **before any information read**. Any header whose low byte isFF returns; upper24 bits have no additional EOS meaning.

Every nonEND opcode, even unrecognized/opaque, reads the BEu32 information word at packet+4 (D20C), then advances to source data packet+8. A12-byte stack descriptor is written in this original order: count=info>>16 tosp+18; source pointer tosp+14; destination=scratchBase+((info&FFFF)<<5) modulo32 tosp+10. Thus descriptor offsets0/4/8 are destination/source/count. The two information fields are unsigned16. No native count,source,destination,packet-length or buffer-capacity guard is introduced by this dispatcher.

The header upper16 controls advancement. After the helper/opaque branch, D2B4..D2BC add4*(upper16-1) to the packet+8 data cursor, giving **next=packet+4*(upper16+1) modulo32**. Upper16=0 has an encoded span4 but still reads its information word atpacket+4, which is also the next header. It is not coerced to8. A lowFF END reads only its four-byte header and never that overlapping word. A host API must distinguish encoded span from required metadata reads, preserve opaque skips, and reject missing buffers/END as host policy. Arithmetic wrap tests do not execute native unaligned/faulting accesses.

## Exact branches and state order

| Low opcode | Before-call state effect | Native target / arguments |
|---|---|---|
| 29 | None | DAF0(descriptor,currentMatrixPointer) atD24C |
| 2C | None | DC98(descriptor,currentMatrixPointer,(header&7FFF)>>8) atD268 |
| 2A | State word OR2, stored atD280 | DC10(descriptor,currentMatrixPointer) atD28C; math unknown |
| 23 | State word OR3, stored atD2A4 | DA30(descriptor,currentMatrixPointer) atD2B0 |
| Every other nonFF | No dispatcher state/helper effect | Encoded skip after metadata read |

State is physically addressed through r13-0x7178. OR2 sets bit1 and preserves every other bit; OR3 sets bits0/1 and preserves every other bit. The dispatcher never resets this state at entry, between packets or before returning. The state read/write happens **before** the matrix-pointer read and helper call for23/2A. Under the previously documented startup r13=803B52C0 assumption, the state label is803AE148; this audit does not assume that register value is live.

The2C mode is exactly seven raw bits8..14, range0..127. Bit15 is cleared before extraction and upper16 does not contribute. Do not restrict the raw mode to sample values0/1/2. The dispatcher observes no helper return value: it resumes its local encoded skip, then overwrites r3 with the next header. On normal END it explicitly loads r3=0 atD2D4. This is an unconditional native return value, not a demonstrated success/error contract. Helpers' scratch/GQR/FPR/FP effects are separate from that result.

Opcode2A's established prefix is stateOR2→matrix pointer read→callDC10. Its boundary-only C source contains further calls; numerical effects and subsequent state/GQR consequences are not modeled. The CPU numerical stream API should reject2A rather than silently skip it or reuse another helper. No2A floating math was executed or emulated by this audit.

## Matrix binding and closed-helper effects

The dispatcher reads the pointer at **r13-0x71FC** afresh for every recognized packet, atD248(29),D260(2C),D288(2A),D2AC(23). Under the prior startup-SDA assumption this is label803AE0C4; its runtime content,matrix initialization,ownership and validity are unknown. The native dispatcher does not cache a matrix pointer for the stream. Opaque and END packets do not read it.

The selected23/29/2C helpers contain no direct or indirect calls; their only op19 transfer is normal `blr`. Complete typed GPR-write coverage across all280 helper words proves no r13 write. All their native memory store base registers are:23→r5;29→r1/r5;2C→r1/r6. There is no direct store through r13. These stores are scratch outputs and,for29/2C,private floating save frames as established in the separate helper audit. Indirect aliases still matter: a scratch destination or frame can physically overlap a global word,matrix bytes,descriptor or source.

Therefore a single explicit immutable matrix binding across a CPU stream is justified **only under the declared closed/nonalias/no-external-mutation scope**: output scratch and helper stack do not overlap matrix data,global pointer/state words,descriptor/source data; the binding and matrix are not changed asynchronously or externally; helpers return under their supported math/input contract. Under those premises these closed helpers cannot change the global matrix pointer or its matrix bytes,so each fresh read yields the same binding. This is conditional proof,not a statement that native aliases or runtime callbacks never exist. A deliberately external-mutation control fixture demonstrates that the original dispatcher would see a newly written pointer at the next recognized call; it is outside the closed API contract.

23/29 do not touch GQR1;2C writes0x08070807 and does not restore it on normal return, as independently proved by the quantization audit. The dispatcher does not read,initialize or reset GQR1. Thus an explicit initial GQR1 is retained until the first executed2C; thereafter it remains0x08070807 across23/29/opaque/END in this closed supported path.2A is excluded. No live GQR0/FPSCR claim follows; declared GQR0=0,RNnearest,NI0,nontrapping and finite consumed/retained numerical support remain separate contracts. Native floating flags and unused lookahead are outside this integer model.

## Validation and conservative integration

Quote from once-only validation: **all256 opcodes;48 upper16/address-wrap boundary cases;65,536 information-extraction cases;256 mode/bit15 cases;262,144 state-OR cases;four ordered traces with91 events;three opaque4-byte info/header-overlap cases—all passed**. State validation exhausts all low16 values across four upper16 patterns, while the original OR-immediate mask proves the unchanged upper bits algebraically for arbitrary32-bit inputs. Information vectors cover all values of both16-bit fields and original masks prove their independence; this is not an enumeration of all2^32 information words. Full raw CSV preserves each case and control event.

The original72-word integer model executes only dispatcher control/integer effects; numerical helpers are opaque hooks. Supported hooks record descriptor/count/source/destination/matrix/mode and the separately proved GQR1 clobber. The2A fixture stops at the unresolved call after its known prefix. These are explicit synthetic bindings and control traces,not native or game execution. The numerical agent independently validates full real-stream scratch results with explicit matrices; this audit does not duplicate or claim that numerical work.

Conservative opt-in API: consume raw packets in original order; copy caller scratch/state/GQR1; invoke only proved23/29/2C CPU fragments with explicit matrix; preserve all unknown-opcode metadata/encoded skips; stop before info on lowFF; return copied scratch and final explicit state/GQR1. Reject2A and unsupported numerical inputs with clear host guards. Do not require opaque packets' unused count/base to fit scratch or read unused matrix values as if a native call occurred. Zero recognized counts and out-of-declared records may be rejected by the numerical helpers' existing host rules; opaque count0 itself has no native math effect. A transactional host failure policy is not native rollback—the original2A path already storesOR2 before calling unknown code.

Unknowns remain actual SDA/global/matrix/scratch binding,initial state and GQRs/FPSCR,aliasing and asynchronous mutation,2A math,full numerical flags/preloads,resource lifetimes and gameplay/render integration. C-only ASM absence is preserved as a source-selection limit; frozen C/math warnings remain applicable. No engine/repository/original/frozen/language/DB file changed, no project opened, no native code executed and no leaked source encountered or used. Root owns integration/docs and final notification.
'''
(OUT/'dispatch-reference.md').write_text(human,encoding='utf-8')
compact={'result':'bounded original dispatcher integer/control and conditional closed-binding proof established','human_report_sha256':sha(human.encode()),'inspection':inspection,'validation':validation,'descriptor':'stack+10{dest},+14{source},+18{count};writecount→source→dest','packet':'BEu32lowFFENDbeforeinfo;everynonFFinfo;nextp+4*(upper16+1)mod32;upper0readsoverlappingnextheader','fields':'countinfo>>16/startlow16<<5;2Cmode(header&7FFF)>>8;bit15ignored','state':'r13-7178;23OR3/2AOR2BEFOREmatrixread/call;noreset;label803AE148onlypriorSDA','matrix':'r13-71FCfreshreadpersupportedcall;label803AE0C4onlypriorSDA','closed_binding':'280typedhelperwords/noGPR13write/noexternalcalls;constantONLYnonalias/noexternalmutation;notruntimeproof','GQR1':'explicitinitialpreserved23/29/opaque/END;2Cclobber08070807normalreturn;2Aunknownreject','return':'r3literal0atD2D4noterrorcontract','unsupported2A':'prefixOR2+matrixread+unknowncallproved;nomath','typed_helper_word_coverage':len(typed),'host_guards':'bounds/declaredspan/knownpositivecount/finiteknownfragment;noopaqueunusedscratch/matrixeffectinvented','native_execution':False,'project_opens':0,'engine_repository_frozen_changes':[],'leaked_source':'none encountered or used'}
(OUT/'dispatch-reference.ai.json').write_text(json.dumps(compact,indent=2)+'\n',encoding='utf-8')
files=[{'path':p.name,'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in sorted(OUT.iterdir()) if p.is_file() and not p.name.startswith('manifest')]
save('manifest.csv',files);digest=sha((OUT/'manifest.csv').read_bytes())
(OUT/'manifest.ai.json').write_text(json.dumps({'result':'finalized','files':len(files),'manifest_sha256':digest,'input_source_guards_reverified':len(inputs),'human_report_sha256':sha(human.encode())},indent=2)+'\n')
(OUT/'manifest.md').write_text(f'# Vertex dispatcher digest\n\nFinalized{len(files)} private artifacts;{len(inputs)} source/input guards reverified unchanged. Manifest SHA-256 `{digest}`. Paired dispatch-reference and complete original/control/domain CSVs retained; no engine/repository/frozen/DB changes.\n')
print(json.dumps({'result':'finalized','files':len(files),'manifest_sha256':digest,'typed_closed_helper_words':len(typed),'input_guards_reverified':len(inputs),'reference':str(OUT/'dispatch-reference.md')},separators=(',',':')))
