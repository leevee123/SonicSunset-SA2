"""Finalize bounded original GQR0 reference, source guards and complete artifact manifest."""
import ast
import csv
import hashlib
import json
import re
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
assert not (OUT / 'gqr0-reference.ai.json').exists()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def rows(path):
    with Path(path).open(newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def save(name, values):
    keys = list(dict.fromkeys(k for r in values for k in r)) or ['result']
    with (OUT / name).open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, keys)
        w.writeheader()
        w.writerows(values)


discovery = json.loads((OUT / 'discovery.ai.json').read_text())
inspection = json.loads((OUT / 'inspection.ai.json').read_text())
validation = json.loads((OUT / 'validation.ai.json').read_text())
all_input_rows = []
for name in ['discovery-input-sha256.csv','inspection-input-sha256.csv']:
    all_input_rows.extend(rows(OUT / name))
for r in all_input_rows:
    assert sha(Path(r['path']).read_bytes()) == r['sha256'], r['path']
source_rows = rows(OUT / 'owner-source-artifacts.csv') + rows(OUT / 'bounded-source-artifacts.csv')
for r in source_rows:
    assert sha(Path(r['path']).read_bytes()) == r['sha256']
native = rows(OUT / 'bounded-original-words.csv')
psq = []
for r in native:
    w = int(r['word'],16)
    if r['entry'] in ['0x800e5388','0x800e54ac'] and w >> 26 in [56,57,60,61]:
        psq.append({**r,'implicit_GQR_index':(w>>12)&7,'W':(w>>15)&1,'access':'paired_load' if w>>26 in [56,57] else 'paired_store'})
assert len(psq)==64 and all(r['implicit_GQR_index']==0 for r in psq)
save('FP-context-implicit-GQR0-consumers.csv',psq)

# The generic context-owner C was selected before this final original-word retention.
dol=(ROOT/'work/sa2-disc/main.dol').read_bytes()
mapping=json.loads((ROOT/'work/dol-elf-mapping-final.json').read_text())
assert sha(dol)==discovery['DOL_sha256']
def offset(va):
    m=next(m for m in mapping['mappings'] if m['address']<=va<m['address']+m['size'])
    return m['dol_offset']+va-m['address']
context_words=[]
for view in ['main','main-sda-v1']:
    base=ROOT/'work/full-decompile/gekko'/view/'export'
    for b in rows(base/'function_body_ranges.csv'):
        if b['entry'] not in ['0x800e563c','0x800e56bc']:
            continue
        for va in range(int(b['range_start'],16),int(b['range_end_exclusive'],16),4):
            position=offset(va)
            w=struct.unpack_from('>I',dol,position)[0]
            context_words.append({'view':view,'entry':b['entry'],'va':hex(va),'dol_offset':hex(position),'iso_offset':hex(0x1e700+position),'word':hex(w),'opcode':w>>26,'field21':(w>>21)&31,'field16':(w>>16)&31,'immediate_u16':w&65535})
save('generic-context-original-words.csv',context_words)
exceptions=rows(OUT/'graph-versus-native-classification-exceptions.csv')
assert all(r['raw_target_matches_graph']=='True' and r['raw_link_bit']=='False' for r in exceptions)
save('final-source-sha256.csv',[{'path':p,'sha256':d} for p,d in sorted({r['path']:r['sha256'] for r in all_input_rows+source_rows}.items())])
sites=rows(OUT/'value-evidence-sites.csv')
site_table='\n'.join(f"| {r['va']} | {r['dol_offset']} | {r['iso_offset']} | {r['word']} | {r['decode_subset']} |" for r in sites)
hashes={r['path']:r['sha256'] for r in all_input_rows}
spec_path=ROOT/'work/full-decompile-fp/Sa2GekkoLanguage/data/languages/ppc_gekko_broadway.slaspec'
embedded_path=spec_path.parent/'ppc_embedded.sinc'
primary_path=ROOT/'work/full-decompile-fp/Gekko.pinned.h'
reference_sha={str(p):sha(p.read_bytes()) for p in [spec_path,embedded_path,primary_path]}
primary_lines=primary_path.read_text().splitlines()
save('primary-GQR-zero-reference-lines.csv',[{'path':str(primary_path),'line':i+1,'text':line,'sha256':reference_sha[str(primary_path)]} for i,line in enumerate(primary_lines) if i+1 in [329,342,343,344,345,884]])
human=f'''# GQR0 in the original main executable

The original startup path writes literal zero to GQR0. A separate global register snapshot saves and later restores GQR0 through a memory word. These facts narrow the previous unknown; they do not prove the register's live value at gameplay drawing calls. This audit changes no engine/repository/original/frozen/database/language file and observes no native execution.

## Bounded scan and source identity

One once-only scan covers all **376,848 aligned words in the two original DOL text sections**. Original DOL SHA-256 `{discovery['DOL_sha256']}` matches real ISO bytes at header-selected DOL offset0x1E700. Exact GQR0 accesses are **two writes and one read**; all GQR0..7 accesses total72. No candidate with reserved bit0 set was accepted. The selector was validated against the immutable local Gekko SLEIGH definitions: primary opcode31; extended opcode339 for `mfspr`,467 for `mtspr`; bit0=0; SPR bits rearranged from their encoded halves. All1,024 SPR selector cases and GQR0..7 table labels were checked. Primary existing pinned Dolphin `Gekko.pinned.h` identifies GQR0 as SPR912/0x390. These are instruction/reference validations, not game-source substitutions.

Complete evidence: `original-text-segments.csv`, `all-GQR-accesses.csv`, `GQR-access-owners.csv`, `instruction-definition-lines.csv`, `SPR-selector-domain.csv` and source SHA guards. Both frozen views were used: context-free `main` and startup-SDA `main-sda-v1`. Generated C was read first; original words resolve the omitted architectural effects. The bounded selection retained704 original words,1,180 exported ASM rows matched original bytes,56 graph-reference rows, and66 distinct source files. Source-scope counts overlap earlier audits and do not add whole-corpus coverage.

| Original instruction VA | DOL file offset | ISO offset | Original word | Bounded decode |
|---|---|---|---|---|
{site_table}

## Startup zero write

DOL entry80003140 calls80003330 at80003144; that helper calls800E3D38 at80003340. At800E3D58 the original executes `li r3,0`, immediately followed at800E3D5C by `mtspr GQR0,r3`. No branch or call intervenes. This is an unconditional zero write once that path reaches the instruction; the generated C for800E3D38 omits the SPR write and only exposes return0. Earlier calls in that helper modify other hardware state; they do not change the immediate literal feeding this write.

Under the pinned primary register definition, zero decodes as store type0/scale0 and load type0/scale0, with type0 named `QUANTIZE_FLOAT`. This describes a declared GQR0=0 contract. It is not evidence that a later draw instruction observed zero, nor exact floating-point equivalence of a port. Existing FPSCR RN/NI/VE uncertainty and frozen SLEIGH quantization limitations remain separate.

## Global snapshot read and restore

Function8010A6B4 constructs r2=802D6AA8 in its first two original instructions. At8010A788 it reads GQR0 into r20, then reads GQR1..7 into the following registers. At8010A7B8 `stmw r20..r31,0x2FC(r2)` stores GQR0's captured word at **802D6DA4**. This original global snapshot covers more than GQRs. C exposes the GQR0 capture as `DAT_802d6da4 = unaff_GQR0`.

Function8010A86C independently reconstructs the same r2 base. At8010A8A8 `lmw r20..r31,0x2FC(r2)` reloads the block; at8010A8AC it writes r20 to GQR0, followed by GQR1..7 restores. This writer is **memory-derived, not a zero initializer**. The nearby byte flags gate other SPR effects, but the GQR block load/write is on both local flag paths. C for8010A86C shows only two zero-byte stores and drops the architectural restores. The snapshot location is inside original DOL BSS and has **no original DOL/ISO file offset or sample bytes**. Analysis-view zeros or an initial BSS policy cannot establish its value at a later restore. Mutation, save/restore order and snapshot integrity remain unknown.

The absolute snapshot-base constructions are in the original instructions; they do not depend on the post-startup r2/r13 SDA assumption. These routines explicitly repurpose r2, so ordinary C calling-convention assumptions and generated void signatures cannot substitute for the original physical-register effects.

## Static callers, context paths and implicit uses

A complete main-text immediate-branch scan finds five exact-entry transfers in this selected path: entry→03330 at03144;03330→E3D38 at03340;80109838→A6B4 at80109964;8010A474→A6B4 at8010A4C0;80109B18→A86C at80109BA4. The latter owner has a return-from-interrupt path. These are original static transfers and source-context evidence, not observed interrupts or complete trigger/caller closure. Indirect calls, interior entry, other carriers and dynamically written/copied code remain outside the search.

Ordinary context owner800E563C explicitly captures GQR1..7 at800E5640..800E5670, into context words+1A8..+1C0. Restore owner800E56BC writes GQR1..7 at800E5714..800E5744. Neither has an explicit GQR0 SPR transfer in the complete main-text scan. Do not assign an unobserved purpose to the preceding context hole or infer a missing GQR0 load. Their C and complete original word selections are retained.

GQR0 is also consumed **implicitly** by paired quantized load/store instructions. The original FP-context functions800E5388 and800E54AC contain64 immediate paired instructions selecting index0:32 loads and32 stores, retained in `FP-context-implicit-GQR0-consumers.csv`. They are not `mfspr` reads and are therefore not included in the explicit three-access count. Generated C's `unaff_GQR0` expressions reflect that dependence. The global register snapshot path includes GQR0, while these ordinary context paths preserve/use it differently. No formal external ABI guarantee or live GQR0 invariant was established by this audit.

## Validation, selection limits and decisions

Quote from the passing bounded scan/value checks: **376,848 text words;72 GQR accesses;GQR0 two writes/one read;1,024 SPR selectors; startup write0; separate snapshot slot802D6DA4;live gameplay GQR0 not proven**. All source/original/mapping/reference hashes were reverified. `generic-context-original-words.csv` adds the ordinary context source words with both-view ownership; all original VA/DOL/ISO locations remain complete.

Inspection v1 stopped before completed output because it assumed every Ghidra direct-call graph row must have a native link bit1. Version2 retains native target and link separately. Four rows (two native sites represented in both views) are matching-target non-link transfers:80003250→8010B458 and8010A504→8010AA2C. This is a graph/classification distinction, not a mismatched original target. The failed v1 and paired failure report are preserved. Startup/global-restore functions were completed C-only and have no individual ASM exports, so original bytes were selected by matching body ranges. Oversized expanded FP C output was truncated; compact structural C selections and complete raw words remain available. No missing effect was filled in from a prototype.

Conservative integration decision: retain an explicit numerical GQR0 contract where needed, and keep raw-data ports as raw data. A path that demonstrably passes the startup write and subsequently preserves its snapshot without intervening mutation would conditionally preserve zero; the present audit does not establish those runtime premises. Do not set a blanket gameplay GQR0=0 assumption from this main-DOL-only scan or remove runtime FP/quantization unknowns.

Remaining unknowns: actual startup reach/execution; live register values at consumers; snapshot mutation/order/ownership; REL/apploader/copied/modified-code writes; asynchronous or external paths; complete ABI and indirect caller closure; FPSCR and exact paired/FMA/quantization semantics. No engine files changed, no projects/databases opened, no installed/frozen language modified, no native game executed, and no leaked original source encountered or used. No usage-limit tool response occurred in this bounded pass. All four team slots remained assigned to independent tasks, so source selection/value validation within this worker ran sequentially.
'''
(OUT/'gqr0-reference.md').write_text(human,encoding='utf-8')
compact={'result':'startup literal-zero plus snapshot save/restore proven statically;live gameplay GQR0 remains unknown','human_report_sha256':sha(human.encode()),'scan':discovery,'bounded_sources':{'source_files':66,'word_rows':704,'ASM_rows':1180,'graph_rows':56,'source_scopes':'complete rawCSV;overlap prioraudits'},'startup':{'entry':'80003140','call03330':'80003144','callE3D38':'80003340','li0':'800E3D58','write':'800E3D5C/E0D5C/FF45C','value':0,'C_omission':True},'snapshot':{'save_owner':'8010A6B4','read':'8010A788/107788/125E88','store':'8010A7B8','base':'802D6AA8','displacement':'2FC','slot':'802D6DA4','slot_file_offset':None,'BSS':True,'restore_owner':'8010A86C','load':'8010A8A8','write':'8010A8AC/1078AC/125FAC','restore_value':'savedmemoryword,notliteral','ownr2construction':True,'C_restore_omission':True},'ordinary_context':{'save_owner':'800E563C','reads':'800E5640..E5670 GQR1..7','context_offsets':'1A8..1C0','restore_owner':'800E56BC','writes':'800E5714..E5744 GQR1..7','GQR0_explicit_access':False,'unassigned_hole_meaning':'unknown'},'implicit_consumers':{'functions':['800E5388','800E54AC'],'paired_index0_loads':32,'paired_index0_stores':32,'not_counted_as_mfspr_reads':True},'primary_zero_fields':validation['architectural_zero_interpretation'],'reference_SHA256':reference_sha,'caller_scope':'5exactentryimmediatebranches maintext;notclosure/execution','graph_v1_failure':'link-bit assumption;v2matchingtarget nonlinksites3250/A504 retained','live_gameplay_GQR0_proven':False,'unknowns':['runtime startup/reach','liveconsumer value','snapshot mutation/order/ownership','othercarriers/copiedcode/async/external','ABI/indirectclosure','FPSCR/exactFP/paired/FMA/quantization'],'engine_repository_frozen_changes':[],'native_execution':False,'project_opens':0,'leaked_source':'none encountered or used'}
(OUT/'gqr0-reference.ai.json').write_text(json.dumps(compact,indent=2)+'\n',encoding='utf-8')
files=[{'path':p.name,'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in sorted(OUT.iterdir()) if p.is_file() and not p.name.startswith('manifest')]
save('manifest.csv',files)
digest=sha((OUT/'manifest.csv').read_bytes())
(OUT/'manifest.ai.json').write_text(json.dumps({'result':'finalized','files':len(files),'manifest_sha256':digest,'distinct_original_analysis_source_files':66,'human_report_sha256':sha(human.encode())},indent=2)+'\n')
(OUT/'manifest.md').write_text(f'# GQR0 audit digest\n\nFinalized{len(files)} private files. Manifest SHA-256 `{digest}`. Paired reference gqr0-reference.md / gqr0-reference.ai.json; complete source/word/selector/caller/implicit-consumer CSVs retained. No engine/original/frozen/DB/language changes.\n')
print(json.dumps({'result':'finalized','files':len(files),'manifest_sha256':digest,'explicit_GQR0_writes':2,'explicit_GQR0_reads':1,'FP_context_implicit_index0_instructions':len(psq),'live_gameplay_GQR0_proven':False,'reference':str(OUT/'gqr0-reference.md')},separators=(',',':')))
