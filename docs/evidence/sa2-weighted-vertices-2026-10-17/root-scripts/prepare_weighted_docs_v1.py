from pathlib import Path
import csv
import hashlib
import json

root = Path(__file__).resolve().parent.parent
work = root / 'work'
stage = work / 'weighted-stage'
repo = Path('C:/decomp/SonicFantasy-master')
sha = lambda b: hashlib.sha256(b).hexdigest()
load = lambda name: json.loads((stage / name).read_text())
snapshot = load('snapshot.ai.json')
applied = load('applied.ai.json')
assert not (stage / 'docs-prepared-v1.ai.json').exists()
for name in ('validation-v1', 'stream-validation-v1', 'weight-domain-v1', 'engine-build-v1', 'evidence-recheck-v2', 'source-review-v1', 'package-v1'):
    assert load(name + '.ai.json')['status'] == 'PASS', name
for key, values in [('engine', applied['engine_after_sha256']), ('docs', snapshot['prior_docs_evidence_sha256'])]:
    assert all(sha((repo / n).read_bytes()) == digest for n, digest in values.items()), key
payloads = {n: (stage / 'original' / n).read_bytes().decode() for n in snapshot['docs_before_sha256']}
sections = json.loads((work / 'dol-elf-mapping-final.json').read_text())['mappings']
table = '| Original function VA | DOL offset | ISO offset | Role |\n|---|---|---|---|\n'
for va, role in [(0x8011D1D4, 'first vertex-stream dispatcher'), (0x8011DA30, 'unchanged op23 math'), (0x8011DAF0, 'unchanged op29 math'), (0x8011DC10, 'unsupported op2A call boundary only'), (0x8011DC98, 'weighted op2C helper')]:
    off = next(s['dol_offset'] + va - s['address'] for s in sections if s['address'] <= va < s['address'] + s['size'])
    table += f'|`{va:08X}`|`{off:X}`|`{off + 0x1E700:X}`|{role}|\n'
addition = (stage / 'model-addition.md').read_text()
assert addition.count('<!-- WEIGHTED_FUNCTION_TABLE -->') == 1
addition = addition.replace('<!-- WEIGHTED_FUNCTION_TABLE -->', table)
evidence_root = 'docs/evidence/sa2-weighted-vertices-2026-10-17'
recheck = load('evidence-recheck-v2.ai.json')
addition += f"\nRead-only provenance recheck v2: {recheck['source_identity_checks']} path/digest identities, {recheck['recorded_digest_references']} recorded references and {recheck['input_ledgers_unchanged']} unchanged ledgers; all four implementation-prefix checks pass. Original, frozen decompilation, primary semantic references and frozen language inputs retain their identities. Eight historical candidate references map to preserved core snapshots; the final stream source hashes match both the prepared and applied files. Exact LF/CRLF adjudication is limited to the two named report fields.\n"
addition += f'\nEvidence index: [weighted reports and complete raw tables](evidence/sa2-weighted-vertices-2026-10-17/README.md).\n'
payloads['docs/SA2_MODEL_DATA_REFERENCE.md'] += addition
short = '''
Oct17WEIGHTED+FULLFIRSTSTREAM: ModelVertexTransform.hcpp EXTENDED ONLY; noCMake/shared/caller/contentchanges/252other254sourceguardsunchanged. Explicitweightedpacket API→base/count/7bitvariant+COPIEDwholeBE32Bscratch;stream API→afterENDoffset/stateBits/GQR1+scratch,explicitinitialstate/GQR1/fixednonaliasedmatrix. GQR0=0/RNnearest/NI0/nontrapping/finiteconsumed+retainedresults;no livebindingproof/FPSCR/discardedlanes/aliases/wrap/faults/unsafeN0/lookahead. Oldunweighted+corevalidatedweightedbodiesunchangedprefixproof.
DC98/11AC98/139398(160words):2Cheaderlowbyte/infohighcount/lowbase,28Brecord=6f32+s16weight24+u16dest26;slot=(base+dest)*32 writes0..23/preserve24..31. Mode(header&7FFF)>>8;bit15ignored;0round32(transform*q),ANYnonzeroFMA(transform,q,old). GQR1DCAC=08070807clobbered/notrestored/weightS16/256exactall65536(-128..127.99609375/+0only). SourceSLEIGH6→3bitscale8→0lossfrozenunchanged;rawDD1C/DD74/DDEC/DE44/DEC4E6679008resolve. Firsttriple3FMAtranslationfirst;secondroundedMULthen2FMA;finalPSQFTZsignedzeroevenNI0;duplicatesreadpriorstoredFTZ/all6oldloadbeforestores/orderpreserved. NativeunusedN+1reads24B(nonzeroN1)/28B(otherpositiveN);hostrequiredrecordsonly/N0reject/declaredspan/fullslotguardsHOSTpolicy.
D1D4/11A1D4/1388D4(72words):FFbeforeinfo/everyotherinfo/encodedadvance4*(upper16+1)nativewrap;23OR3beforematrix/call/29retain/2CclobberGQR1/opaqueSKIPretain/2AOR2thenunknowncallREJECTEDhost. Matrixfreshreadr13-71FCatD248/D260/D288/D2AC,stater13-7178;absolutelabels803AE0C4/803AE148conditionalpriorSDA. Hostfixedmatrixonlynoaliasnoexternalmutation/280closedhelperwordsnocallsnor13writes/storeRA13;notruntimeproof. Native r3literal0D2D4;hostafterENDmetadataNOTnativere turn. Readerprevalidation/64bitbounds/failureatomiccopyHOSTpolicy;opaqueunusedmatrix/scratchnocheckinvented.
RealISO/FST2428/479024A4 SONICMDL.PRS102331→136360 bytes hashesd8f90e6c.../b7ea586e...;100streams254packetincl100END3167records+72maskwordsrechecked.83weighted830records4980words;variants0/1/2packets38/2/43records412/6/412/allbit15;counts1..66/weights0..255(30zero30at255)/187distinct;no256negativeinSAMPLE/noclampinference. Rawdest0..317/base+dest2..317/248distinct/noinpacketduplicates/declaredexact28*count/notails.81lookahead28B+2lookahead24Bavailable/65nextEND18next2C.65weightedstoredstreams sequences2alone27/0→2fifteen/0alone21/0→1→2one/0→1one;57same-streampairs0destintersection;pooled248targetsallmultiple streams/op29overlapNOTruntimeidentity/weightnormalization/traversalproof.
314weightedcases249real83packets*3matrices+65synthetic/2567recordrows/13326784WHOLEscratchB matchC++/94662originalsteps/all160helperwords;CRT82144lanerows57802distinct0diff.309streamcases300real100streams*3matrices+9synthetic/5062656WHOLEB/9507slots/stateGQRendallmatch/257538originalsteps470calls/352wordsverified345successfulexecuted7only2Aarm;originalBL/LR/SP/descriptors+explicitSDAglobalsNOTformulaonly. StreamCRT245856laneops160219distinct0diff. Full65536weights8C++batches393216floatwords2097408scratchBpass. Weighted12preserve17reject/stream6preserve6reject;0productioncorrection/strictMSVCW4WX+fullWinx64NinjaDebugEDITORONcompilelinkPASS/strictFPONLYsameunit/invocationEmbeddedunchanged. PackagedWeighted-Vertex-CheckPASS readsuserdisc/noactualmedia/ownsyntheticcaches;mathchecknotmodeldisplay. Initialmatrices/state/cachedeclaredtestinputs;nohardware/Dolphin/gameexecution.
Failuresretained:hostharnessC4244typedarrayfix/samplehexparsev1→v2/dispatchclassifiercompare10,11v1→v2/streamfinalISOmetadataformatv1→v2;nooriginal/productionchanges. Historicalcandidatehashesmappedcore-validatedsnapshot;finalsourceappendedstreamonly. Evidenceweighted-vertices-2026-10-17/README.md+rawCSV+pairedreports. Noleakedsource/frozenlanguage/DBchange. Remaining2A/liveGQR0FPSCR/matrixstackinitmath/cachelifetime/alias/materialtopologyattrFIFO/animproviderskeleton/ABIownership/modelrender/levelsphysicscamera→provenLua;fullgameNOTdone/corpuscountsunchanged.
'''.replace('nativere turn', 'nativereturn').replace('multiple streams', 'multiplestreams')
model_ai = payloads['docs/ai/SA2_MODEL_DATA.md']
model_ai = model_ai.replace('Remainingweighted2C/2A/', 'Remaining2A/liveweightedbindings/')
payloads['docs/ai/SA2_MODEL_DATA.md'] = model_ai + short
engine = '''
## 2026-10-17: weighted vertices and complete first-stream CPU dispatch

| Engine file | What changed | Why | SA / Shadow effect |
|---|---|---|---|
| `src/Importers/SA2/ModelVertexTransform.h` | Add explicit weighted packet and full first-stream result/API types with copied scratch, state and GQR1 metadata. | Expose original8011DC98/8011D1D4 behavior with caller-supplied matrix/cache/state. | Additive SA2 API; no existing caller or type changes. |
| `src/Importers/SA2/ModelVertexTransform.cpp` | Add exact signed16/256 weights, mode0 rounded products/nonzero fused accumulation, additive indexed destinations, ordered writes and stream dispatch through existing23/29 and new2C. | Match original arithmetic, state OR3, GQR1 clobber, opaque skipping and END under the documented finite Float32 contract. | Parallel CPU path; old helper bodies unchanged. No shared renderer, main, pools, Lua, gameplay or content changes. |

CMake and its source-local strict FP settings are unchanged.252 other guarded source/content files retain their hashes.314 weighted cases/13,326,784 complete scratch bytes,309 streams/5,062,656 complete bytes plus all state/GQR1/end metadata, and65,536 signed weights through8 C++ batches pass;12+6 preservation and17+6 rejection fixtures pass. Strict MSVC and full Windows x64 MSVC/Ninja Debug EDITOR ON compile/link pass. Strict FP remains limited to this unit; existing invocation-only Embedded workaround unchanged. No production correction after reference comparisons.

This does not establish live matrix/GQR0/FPSCR/cache/animation/material bindings, render a model or add gameplay. Unknown2A is rejected; native unsafe lookahead, count0, aliases/wrap/faults/discarded lanes/FPSCR are excluded by explicit host policy. Linux/EDITOR OFF and existing gameplay were not rerun. See the dated model-reference section, architecture twins and complete paired weighted evidence; no leaked original source was used. Earlier weighted-unknown statements describe the earlier pass, superseded by these explicit APIs.
'''
payloads['docs/ENGINE_CHANGES.md'] += engine
arch = '''
## 2026-10-17 weighted and full-stream CPU vertex path

`Importers/SA2/ModelVertexTransform.h/.cpp` now also handles weighted2C packets and complete first streams containing23/29/2C/opaque skips/END. Caller inputs remain explicit:12 raw matrix words, initial BE32-byte scratch slots, and (for streams) initial state bits/GQR1. Weighted records carry six floats, signed16/256 weight and unsigned destination added to the packet base. Mode0 overwrites rounded products; every nonzero variant fuses accumulation. Ordered repeated writes and final PSQ signed-zero flushing are preserved. Complete-stream results own scratch and return after-END offset plus modeled state/GQR1;23 ORs state3 and2C leaves GQR1=08070807.2A remains unsupported. Native dispatch reads its matrix global for each call; fixed binding is conditional on nonalias/no external mutation, not a captured runtime fact.

The existing Float32 finite/GQR0=0/nearest/NI0/nontrapping contract and host bounds/environment guards apply. Original unused lookahead/unsafe zero counts/aliases/wrap/faults/discarded lanes/FPSCR are excluded; unknown packets do not gain invented unused-value checks. Existing unweighted and validated weighted function bodies retain exact prefixes. CMake/strict options and252 other source/content files are unchanged; no SA/Shadow/shared rendering/main/pools/Lua/content/current callers are altered. No speculative prefab or renderer wiring is added.

314 weighted packet cases,309 complete streams and all65,536 signed weights through actual C++ pass complete-byte/metadata comparisons against independent original-word references. Host fixtures, strict MSVC, full Windows x64 MSVC/Ninja Debug EDITOR ON compile/link and the media-free Weighted-Vertex-Check package pass; invocation-only Embedded workaround unchanged. No game/hardware/Dolphin runtime claim, Linux/EDITOR OFF or old gameplay retest. Live matrix-stack/cache/animation/provider/material/GX/ABI bindings and complete SA2 rendering/gameplay remain unfinished. See SA2_MODEL_DATA_REFERENCE and ENGINE_CHANGES with twins and weighted evidence.
'''
payloads['docs/ARCHITECTURE.md'] += arch
arch_short = '''
Oct17current:ModelVertexTransform.hcpp2existingfilesEXTENDED/CMakeunchanged/252other254sourcecontentguardsunchanged. Explicitweighted2Cpacket +fullfirststream23/29/2C/opaque/END APIs→wholeCOPIEDBE32Bscratch/stateGQR1/endmetadata;no currentcallers/sharedSA/Shadow/main/render/pools/Lua/contentchanges. Existingunweighted+validatedweightedbodiesunchangedprefixproof. GQR0=0/RNnearest/NI0/nontrapping/finiteconsumed+retainedresults/noalias/noexternalmutation;nativefault/wrap/lookahead/N0/discardedlanes/FPSCRexcluded/hostguardspolicy. NativeDC98s16/256exact/0roundedproduct/ANYnonzeroFMA/additiveindexedorder/FTZstoredduplicates;D1D4freshmatrixglobalpercall/23OR3/2Cclobber08070807/2Areject. All314weighted+309streams+65536weightdomainC++casesPASS/wholebytesmetadata;strictMSVC/fullWinx64NinjaDebugEDITORONcompilelink+Weighted-Vertex-CheckPASS/sourceLOCALstrictFPsameunit/invocationEmbeddedunchanged. No hardware/Dolphin/gameplayrun/LinuxEDITOROFFretest. UnknownliveGQR0FPSCR/matrixstack/animproviders/cachelife/materialtopologyattrFIFO/ABI/2A/render→levelsphysicscameraLuaremain. Fulladdresses/layout/formulas/failureversions/sourcehashes→SA2_MODEL_DATA/human+evidence/sa2-weighted-vertices-2026-10-17;ENGINE_CHANGESlists2files;corpuscountsunchanged/notfullgame/noleakedsource/frozenDBchanges.
'''
for n in ('docs/ai/ARCHITECTURE.md', 'docs/ai/ARCH_IMPORTERS.md', 'docs/ai/ENGINE_CHANGES.md'):
    payloads[n] = payloads[n].replace('/GPU/weighted2C2A/gameplay.', '/GPU/liveweightedbindings/2A/gameplay.')
    payloads[n] += '\n2026-10-17 current addition (earlier standalone helper limits remain historical):\n' + arch_short
progress = '''
## 2026-10-17 progress: weighted vertices and ordered stream execution

The engine now calculates weighted model vertices and processes complete first vertex streams under explicit matrix/cache/state/Float32 assumptions. Native8011DC98 signed16/256 weight conversion, mode0 initialization, every-nonzero fused accumulation, additive indices and repeated-destination ordering are reproduced. Dispatcher8011D1D4 preserves opaque stepping/END, state OR3 and GQR1 clobber. Native2A math remains unknown and is rejected.

Completed this pass:314 weighted cases (83 real packets, three declared matrices,65 synthetic),309 full-stream cases (100 real streams, three matrices,9 synthetic), all65,536 signed weights in8 actual C++ batches,12/17 weighted and6/6 stream preservation/rejection fixtures. Complete scratch bytes and metadata match independent original-word interpreters, with separate exact-rational/CRT operation checks and zero differences. Full Windows x64 MSVC/Ninja Debug EDITOR ON compile/link passes; strict FP is source-local, invocation-only Embedded workaround unchanged. The self-contained Weighted-Vertex-Check package passes against the original read-only disc; it is a calculation test. The existing Chao preview is still the visual preview.

Only ModelVertexTransform.h/.cpp changed; CMake and252 other guarded source/content files are unchanged. Existing unweighted and weighted core bodies are preserved; there are no new runtime callers, Lua prefabs or shared SA/Shadow changes. Paired model/architecture/importer/engine/progress docs and full raw evidence include every native address, file offset, sample count, conservative decision, limitation and failed script version. No leaked source, frozen-language or project mutation occurred.

Not finished:2A, live GQR0/FPSCR, initialized matrix stack and animation/provider/skeleton traversal; cache ownership/lifetime/alias behavior and actual cross-stream order; materials/attributes/topology/GX FIFO; complete rendering/ABI/indirect calls; levels/collision/objects/player physics/camera and Lua prefab integration. Matrices/state/cache are supplied tests, not observed gameplay bindings. Generated corpus counts remain unchanged:60320 C+2530 ASM from95 RELs;65146 canonical candidates+one SDA alternative;21 unowned sites. These counts do not mean the game is fully understood or ported. Existing gameplay/Linux/EDITOR OFF were not newly run.

Details and complete CSV evidence: SA2_MODEL_DATA_REFERENCE.md, its AI twin and evidence/sa2-weighted-vertices-2026-10-17/README.md. Next work should close matrix/animation/cache/material bindings from originals and the unsupported2A path without guessing.
'''
payloads['docs/SA2_DECOMPILATION_PROGRESS.md'] += progress
payloads['docs/ai/SA2_DECOMPILATION.md'] = payloads['docs/ai/SA2_DECOMPILATION.md'].replace('/GPU/weighted2C2A/gameplay.', '/GPU/liveweightedbindings/2A/gameplay.') + arch_short
index_old = 'explicit Float32 vertex calculations / drawing setup'
assert payloads['docs/ai/README.md'].count(index_old) == 1
payloads['docs/ai/README.md'] = payloads['docs/ai/README.md'].replace(index_old, 'explicit Float32 unweighted/weighted vertex calculations and complete first-stream dispatch / drawing setup')
payloads['docs/ai/README.md'] += '\n2026-10-17 SA2 weighted/stream status and evidence: `SA2_MODEL_DATA.md`, `SA2_DECOMPILATION.md`, `ARCH_IMPORTERS.md`, `ENGINE_CHANGES.md`; human `docs/evidence/sa2-weighted-vertices-2026-10-17/README.md` with paired reports/rawCSV. Explicit CPU path only;2A/live binding/render/gameplay remain.\n'

evidence = {}
for directory in ('sa2-weighted-transform-v1', 'sa2-weighted-transform-v1/stream-v1', 'sa2-weight-quantization-v1', 'sa2-weighted-samples-v1', 'sa2-vertex-dispatch-v1', 'weighted-stage'):
    for source in sorted((work / directory).iterdir()):
        if source.is_file() and source.suffix in ('.md', '.json', '.csv', '.jsonl', '.py') and source.name not in ('model-addition.md',) and not source.name.startswith(('docs-', 'final-audit')):
            evidence[directory + '/' + source.name] = source.read_bytes()
    if directory in ('sa2-weighted-transform-v1/stream-v1',):
        for name in ('final_audit_v1.py', 'final_audit_v2.py', 'final-audit.ai.json', 'final-audit.ai.md', 'final-audit.md'):
            evidence[directory + '/' + name] = (work / directory / name).read_bytes()
scripts = ['prepare_weighted_stage_v1.py', 'compile_weighted_data_v1.py', 'compile_weighted_data_v2.py', 'run_weighted_host_fixtures_v1.py', 'validate_weighted_weight_domain_v1.py', 'validate_weighted_data_v1.py', 'prepare_vertex_stream_extension_v1.py', 'compile_vertex_stream_data_v1.py', 'run_vertex_stream_host_fixtures_v1.py', 'check_weighted_scope_preservation_v1.py', 'check_weighted_scope_preservation_v2.py', 'validate_vertex_stream_data_v1.py', 'apply_weighted_port_v1.py', 'build_weighted_engine_v1.py', 'prepare_weighted_docs_v1.py', 'weighted_data_check.cpp', 'vertex_stream_data_check_iso.cpp', 'build_weighted_data.cmd', 'build_vertex_stream_data.cmd']
for name in scripts:
    source = work / name
    if source.exists(): evidence['root-scripts/' + name] = source.read_bytes()
for name in ('compile-v1.raw.log', 'compile-v2.raw.log', 'stream-compile-v1.raw.log', 'engine-build-v1.raw.log'):
    source = stage / name
    if source.exists(): evidence['weighted-stage/' + name] = source.read_bytes()
manifest_rows = [{'path': name, 'bytes': len(data), 'sha256': sha(data)} for name, data in sorted(evidence.items())]
import io
f = io.StringIO(newline=''); writer = csv.DictWriter(f, fieldnames=['path', 'bytes', 'sha256']); writer.writeheader(); writer.writerows(manifest_rows)
evidence['manifest.csv'] = f.getvalue().encode()
readme = '''# SA2 weighted vertex evidence, 2026-10-17

Original GSNE8P rev0 weighted helper8011DC98 and first-stream dispatcher8011D1D4; explicit finite Float32 assumptions, copied scratch and supplied matrix/state/GQR1. No native hardware, game or Dolphin execution;2A math and live bindings remain unknown.

- `sa2-weighted-transform-v1/oracle.md`:314 weighted cases, original arithmetic/order, complete raw operations/load/store/slot tables and source hashes.
- `sa2-weighted-transform-v1/stream-v1/report.md` and `final-audit.md`:309 full streams through original control flow; descriptors, state/GQR1, arithmetic audit and remaining2A boundary.
- `sa2-weight-quantization-v1/weight-reference.md`: all65,536 signed weights, native GQR1 clobber and frozen SLEIGH scale-loss evidence.
- `sa2-vertex-dispatch-v1/dispatch-reference.md`: control/domain cases, conditional binding proof and raw original words.
- `sa2-weighted-samples-v1/summary.md`, `storage-digest.md`, `lookahead-corroboration.md`: original ISO/FST/PRS sample revalidation, bounded stored overlap and exact unused pipeline reads.
- `weighted-stage/validation-v1.md`, `stream-validation-v1.md`, `weight-domain-v1.md`, host/build/preservation/evidence/package reports: independent C++ comparisons and guarded scope.

Raw CSVs remain complete, readable reports have compact twins, failures/scripts are preserved. `manifest.csv` hashes exact copies; it excludes itself and this index pair. Binary media are not copied. Case file paths retain original scratch-work locations; the media-free test package supplies its own compressed synthetic initial caches and uses the user's disc for real input. The old candidate identities in early C++ reports are mapped to preserved core-validated hashes in the evidence recheck, while final stream source hashes bind the current implementation. Repository documentation/source guard snapshots are historical pre/post identities, not claims that every old candidate path remains unchanged.
'''
evidence['README.md'] = readme.encode()
evidence['README.ai.json'] = (json.dumps({'scope': 'weighted2C+firststream23/29/2C explicitcontract; no livebindings/2A/render/gameplay', 'weighted_cases': 314, 'stream_cases': 309, 'all_s16': 65536, 'evidence_files': len(manifest_rows), 'raw_CSVs': sum(n.endswith('.csv') for n in evidence), 'manifest_sha256': sha(evidence['manifest.csv']), 'native_or_dolphin_execution': False}, indent=2) + '\n').encode()
for name, data in evidence.items(): payloads[evidence_root + '/' + name] = data
payloads = {n: v.encode() if isinstance(v, str) else v for n, v in payloads.items()}
for name, data in payloads.items():
    target = stage / 'prepared' / name
    target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
report = {'status': 'prepared', 'docs_before_sha256': snapshot['docs_before_sha256'], 'engine_after_sha256': applied['engine_after_sha256'], 'docs_sha256': {n: sha(b) for n, b in payloads.items()}, 'docs_files': len(payloads), 'modified_existing_docs': len(snapshot['docs_before_sha256']), 'evidence_copies': len(evidence), 'raw_CSV_files': sum(n.endswith('.csv') for n in evidence), 'evidence_root': evidence_root}
(stage / 'docs-prepared-v1.ai.json').write_text(json.dumps(report, indent=2) + '\n')
(stage / 'docs-prepared-v1.md').write_text(f"# Weighted documentation prepared\n\n{len(payloads)} files:10 existing human/twin/index documents plus{len(evidence)} evidence copies including{report['raw_CSV_files']} complete CSVs. Source/doc preimages guarded; current explicit contract, failures and remaining unknowns documented.\n")
print(json.dumps({k:v for k,v in report.items() if k not in ('docs_before_sha256', 'engine_after_sha256', 'docs_sha256')}))
