"""Finalize paired bounded geometry grammar and source/output manifest once."""
import csv
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent
assert not (OUT / 'geometry-reference.ai.json').exists()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def rows(name):
    with (OUT / name).open(newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def save(name, values):
    keys = list(dict.fromkeys(k for r in values for k in r))
    with (OUT / name).open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, keys)
        w.writeheader()
        w.writerows(values)


inspection = json.loads((OUT / 'inspection.ai.json').read_text())
validation = json.loads((OUT / 'validation.ai.json').read_text())
sources, native, scopes = rows('source-artifacts.csv'), rows('original-words.csv'), rows('function-scopes.csv')
for r in sources + rows('input-sha256.csv') + rows('validation-inputs.csv'):
    assert sha(Path(r['path']).read_bytes()) == r['sha256'], r['path']
scope_by_entry = {r['entry']: r for r in scopes}
core = inspection['core_functions']
function_table = '\n'.join(f"| {e} | {scope_by_entry[e]['dol_offset']} | {scope_by_entry[e]['iso_offset']} |" for e in core)
focus = [r for r in native if r['entry'] in core and (r['opcode'] in ['11', '10', '13', '42', '21'] or r['opcode'] == '31' and r['xo'] in ['0', '32', '104'])]
save('count-mask-compare-evidence.csv', focus)

# The initial broad output-store selection also retained one non-MMIO dirty-flag store.
# Keep the original complete candidate CSV; classify it explicitly rather than calling all FIFO.
classified = []
for r in rows('FIFO-output-stores.csv'):
    is_fifo = int(r['immediate_s16']) == -32768
    classified.append({**r, 'classification': 'FIFO store through original lis CC01 base' if is_fifo else 'non-FIFO dirty-state store; retained broad candidate', 'is_FIFO_store': is_fifo})
save('output-store-classification.csv', classified)
fifo_count = sum(r['is_FIFO_store'] for r in classified)
non_fifo_count = len(classified) - fifo_count
assert non_fifo_count == 1
empty_emitters = [r for r in scopes if r['entry'] in ['0x8011d678', '0x8011d788', '0x8011d8e0', '0x8011da04', '0x8011ffd0', '0x80120124']]
for emitter in empty_emitters:
    words = [r for r in native if r['entry'] == emitter['entry']]
    assert len(words) == 1 and int(words[0]['word'], 16) == 0x4e800020

human = f'''# Original inner geometry records: bounded static reference

The seven original helpers establish signed run-count words, signed scratch indices, explicit record strides and skip rules. The real Sonic data validates73 packets,952 runs and6,561 records under the helper-derived layouts. This is a raw-data contract, not a drawing, topology, attribute, material or runtime branch reconstruction. No engine/repository/original/frozen/DB/language file was changed.

## Sources and coordinates

Frozen generated C was read first in both context-free `main` and startup-SDA `main-sda-v1`. The successful seven core functions were exported C-only, so requesting their individual ASM files failed because those files do not exist. This was a source-selection limitation, not a native analysis failure. Matching function body ranges in both catalogs select the original DOL words directly. Complete source/path/SHA metadata and complete original words are in `source-artifacts.csv`, `input-sha256.csv`, `function-scopes.csv`, `original-words.csv`, `retained-assembly.csv`, `direct-calls.csv` and `critical-original-words.csv`.

| Original helper VA | DOL file offset | ISO offset |
|---|---|---|
{function_table}

Original DOL SHA-256 `{inspection['DOL_sha256']}` matches the real ISO at header-selected DOL base `{inspection['DOL_ISO_base']}`. The audit retains713 original words across34 core/emitter/GPR-helper scopes,104 source artifacts,244 exported ASM rows matched to original bytes, and156 direct-call rows. A bounded pure decoder was reused from the prior immutable audit with local convenience labels for a few instruction forms; unsupported words remain raw/unclassified. No original decoder was overwritten or project opened.

Incoming r3 is the data pointer (or pointer-array for20158), r4 is the scratch base, r5 the information parameter. Original save helpers preserve those inputs; C's apparent aggregate return from a GPR-save helper is ABI loss. The six bounded save/restore entry variants were validated through their original first `blr`, consisting only of GPR stores/loads through r11 and return. No scratch allocation size or full public ABI follows from this.

## Common run and index grammar

Let `information` be the helper's raw r5 parameter, `runCount=information&0x3FFF`, and `skips=(information>>14)&3`. These masks are exact original rotate/mask instructions, not inferred topological fields. For each run, read a big-endian signed16 count word and advance two bytes. If negative, negate the full sign-extended32 value; the sign does not alter any other branch in these seven helpers. Therefore raw8000 becomes magnitude32768, not zero or -32768. The run emits the magnitude's low16 to `0x80101948(0x98,0,count16)`.

Every record's index is loaded by `lha`, then shifted left5 modulo32 and added to the scratch base. It is a signed16 index, not an unsigned16 index. Negative indices therefore address before the scratch base modulo native32-bit arithmetic. A raw host reader should preserve them without dereferencing or inventing a scratch-capacity rejection.

Neither the outer run loop nor inner record loop has a zero precheck. Each is a do-while: process first, decrement the32-bit counter, then compare with zero. With an initial zero the arithmetic counter would require2^32 iterations to reach zero again, if memory and all side effects survived. In particular an inner zero count passes zero to the begin helper and still enters its record body. A host parser's rejection of runCount0 or magnitude0 is an explicit safety policy; an empty list would not reproduce the original loop.

Examples and exact native coordinates are retained in `count-mask-compare-evidence.csv`: D594 masks r5 atD5B0/D5B4, reads run count atD5E0, negates atD5F4, reads index atD610, shifts atD618, advances atD640, and loops atD64C/D65C. Corresponding complete words for all seven helpers remain in CSV with VA/DOL/ISO coordinates.

## Explicit per-record layouts

All sizes below are16-bit input words. Every run begins with its count word; no separate per-run alignment was observed. The original helper receives no outer encoded packet length, so its cursor need not stop at the packet's declared end.

| Helpers | Index and following words | Record stride |
|---|---|---|
| 8011D594 /8011D6A4 /8011FEF4 | Read signed index; skip `skips` words | 1+skips |
| 8011D7B4 | Read signed index and two signed16 words; no information-based skips | exactly3 |
| 8011D91C | Read signed index; skip two words and `skips` further words; the two skipped words are not loaded | 3+skips |
| 8011FFF4 | Read signed index and two signed16 words, then skip `skips` words | 3+skips |

D7B4 atD870/D878 loads the two following signed words, with three separate cursor increments and no high-parameter skip. D91C atD9A8 simply adds four bytes before the additional skip atD9CC. FFF4 at1200B8/1200C0 loads the pair and1200EC adds the masked extra skip. Thus D91C and FFF4 share raw framing but differ in which fields they consume. Preserve every trailing raw word and its offset; do not label all tails as emitted attributes.

The scalar helpers D594/D6A4/D7B4/D91C load scratch binary32 slots at0,4,8 and12,16,20. The alternate FEF4/FFF4/20158 helpers load0,4,8 and a raw32-bit word at24 (`lwz`, for example FF90/1200D8/120348). C's float-pointer type is not proof that word24 is a float. D7B4/FFF4's additional r6 argument selects the literal8 if zero, otherwise12 when configuring numeric attribute13 throughD44; those numeric calls do not establish a UV/attribute name or unit.

Only original outer op40 selects the first family, while41/42 select pair-layout paths; actual selected path depends on original header/global state. A conservative raw API can require an explicit layout choice, restrict compatible opcodes, and retain declared packet bytes, records-end offset and padding. It must not infer the branch from filename or sample similarity. Grouped20158 should remain separately unsupported until its explicit pointer-array contract is represented.

## Grouped helper80120158

This function mutates caller-supplied32-bit stream pointers, rather than consuming a single pointer. It uses r5&0x3FFF runs and a separate unmasked r7 parameter k. Its numeric setup and per-record stream loops cover indices0..k inclusively with unsigned comparisons. The first pointer's signed run count alone determines the magnitude; before each run every other stream pointer is advanced two bytes, without reading or comparing those streams' count words.

For each record it reads/advances the signed index from stream0, performs its scratch reads, then loops over streams0..k. For stream0 it reads/advances two signed16 following words. For every other stream it first skips one word (its index), then reads/advances two signed16 words. Thus each stream advances six bytes per record, and two per run header; counts or indices in secondary streams are not checked for agreement. All pointer-array mutations are original stores; no bounds checks are established. The initial other-pointer advance is unrolled in blocks of eight plus remainder but preserves one+2-byte write to each of k other pointers. Full grouped source/words remain in the bundle; no real grouped sample or native execution validates this path.

## Output-store C omissions

Generated C retains only the last of several stores to the same MMIO address. Original emitter words prove three ordered `stfs` writes for each scalar triple (for example D694/D698/D69C), two ordered `sth` writes for the following pair (D8E8/D8EC and12012C/120130), and one `stw` for raw scratch word24 (FFD8/12013C). These form no verified complete GPU transcript or topology claim. The begin helper101948 writes a byte at101A00 and a halfword at101A04 after its state synchronization logic; generated C loses the byte store. Its caller's first raw argument is98 and second0.

The initial broad output-store selector retained39 candidate words, including one non-FIFO dirty-state store at1019E0. Final `output-store-classification.csv` explicitly distinguishes **{fifo_count} actual selected FIFO stores and{non_fifo_count} non-FIFO candidate**; `validation.ai.json`'s older `FIFO_store_words:39` is a broad-selection count, not39 MMIO writes. The original candidate CSV remains complete. The six named end emitters are each a single original `blr`; no hidden end-marker write is present in those bounded bodies. Existing quantization/FPSCR/GQR decompiler limitations remain applicable; this audit does not simulate any FP conversion or MMIO.

## Real data and validation

Decoded Sonic bank136360 bytes SHA-256 `b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963`; compressed Sonic102331 bytes are at ISO0x479024A4, SHA-256 `d8f90e6c724e709b8d3431e725a5db1d1a096bdf5118d2ecca9ad356e7862d99`. These identities and original loader provenance are reused from the completed outer-stream audit. All sample packet/run/record offsets are decompressed-file offsets with no direct PRS/ISO coordinate. Original code offsets are separately mapped in the raw evidence.

Quote from once-only validation: **73 real geometry packets;40,582 declared data bytes;952 count-led runs,675 positive and277 negative;6,561 records; absolute count range3..60; signed index range0..508.** op40 accounts for25 runs/190 records; op41 for927 runs/6,371 records. Records finish with72 padding bytes in total; each packet's padding is empty or0000. All raw data, counts, indices, trailing words and padding offsets are retained in `sample-packet-layouts.csv`, `sample-runs.csv`, `sample-records.csv`.

The66 op41 packets were parsed under both explicit pair layouts; the7 op40 packets under index-plus-skips, giving139 structural layout parses. Every real information value has skips0 and no outer grouping. Therefore these real bytes do not distinguish the nonzero-skip paths, cover op42 or prove runtime branch selection. The source establishes those distinctions; synthetic cases cover all four skip values and all three layouts. Exhaustive65,536 count cases,65,536 information/mask cases and65,536 signed-index shift cases passed, with17 fixtures including raw8000 count, negative indices and separate host zero rejections. These are integer/metadata checks, not execution of the original unsafe loops.

## Scope decisions and unknowns

The conservative integration contract is an additive raw reader with explicit layout, raw signed run word, raw signed index plus every trailing word, source offsets, declared bytes, records-end and padding. Reject zero outer/run counts and truncated/out-of-declared-span records as host policy. Keep negative count sign and negative indices. Do not dereference scratch pointers or infer triangle winding, topology, UV units, materials, complete GPU order, FP equivalence, cache selection or gameplay.

Unknowns remain actual helper selection/global and header state, grouped real data/capacity/aliases, scratch allocation and lifetime, semantic names and units of output data, complete output ordering/state around these functions, malformed runtime behavior and other banks/versions. No leaked source was encountered or used. No Ghidra projects or native game execution were opened/run. All four team worker slots were active; this worker performed the count/cursor and output-store questions sequentially while independent parent/team scopes proceeded. Root owns engine/docs integration; no engine files changed in this audit.
'''
(OUT / 'geometry-reference.md').write_text(human, encoding='utf-8')
compact = {
    'result': 'bounded original count/index/stride grammar established; no native drawing/runtime claim',
    'human_report_sha256': sha(human.encode()),
    'core_functions': [{k: scope_by_entry[e][k] for k in ['entry', 'dol_offset', 'iso_offset', 'ranges', 'words']} for e in core],
    'source_audit': inspection,
    'common': {'run_count': 'information&3FFF;native do-while,zero wraps2^32ifmemorysurvives', 'run_header': 'BEs16;negate negative in32bits;raw8000→32768;zero likewise2^32inneriterations', 'index': 'BEs16<<5 modulo32 +scratchbase;negative preserved', 'information_skips': '(information>>14)&3 EXACTMASK;distinctouterpendingunmaskedexpression'},
    'layouts_halfwords': {'D594_D6A4_FEF4': 'readindex;skipg;stride1+g', 'D7B4': 'readsignedindex+signedpair;stride3 ignoresg', 'D91C': 'readindex;skip2+g;stride3+g;pairNOTloaded', 'FFF4': 'readsignedindex+signedpair;skipg;stride3+g', '20158': 'externalmutablepointerarray;runheaderfrom0;skipotherheaders;stream0index;foreach0..k secondaryskipindexthenreadpair;eachstreamstride3'},
    'scratch_fields': {'scalar_paths': 'lfs0,4,8/12,16,20', 'alternate_paths': 'lfs0,4,8 + RAWlwz24;Cfloatpointerdoesnotestablishword24type', 'units_names': 'unknown'},
    'setup_numeric_parameter': 'D7B4/FFF4r6zero→8,nonzero→12fornumericattribute13;notUVmeaningproof',
    'output': {'classified_FIFO_stores': fifo_count, 'broad_candidates': len(classified), 'non_FIFO_candidates': non_fifo_count, 'validation_counter_correction': 'FIFO_store_words39wasbroadselection,notallMMIO', 'C_loss': 'scalartriples3stfs→last;pair2sth→last;beginbyte+halfword→last', 'empty_end_helpers': [r['entry'] for r in empty_emitters], 'complete_GPU_transcript': False},
    'sample_validation': validation,
    'host_policy': ['explicitcompatiblelayout/opcode','zeroouter/runreject','bounds/declaredspanreject','noindexdereference','keeprawsigns/tails/offset/padding','groupedunsupported'],
    'unknowns': ['runtimepath/header/globalstate','realgroupdata/capacity/aliases','scratchallocation/lifetime','topology/attribute/material/units','fullGPU/FP','otherbanks/versions/malformedexecution'],
    'source_selection_limit': '7successfulcorefunctionsC-only/noindividualASM;matchedcatalograngesselectoriginalwords',
    'engine_repository_frozen_mutations': [], 'project_opens': 0, 'native_execution': False, 'leaked_source': 'none encountered or used'
}
(OUT / 'geometry-reference.ai.json').write_text(json.dumps(compact, indent=2) + '\n', encoding='utf-8')
files = [{'path': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())} for p in sorted(OUT.iterdir()) if p.is_file() and not p.name.startswith('manifest')]
save('manifest.csv', files)
manifest_sha = sha((OUT / 'manifest.csv').read_bytes())
(OUT / 'manifest.ai.json').write_text(json.dumps({'result': 'finalized', 'files': len(files), 'manifest_sha256': manifest_sha, 'source_artifacts_reverified': len(sources), 'human_report_sha256': sha(human.encode())}, indent=2) + '\n')
(OUT / 'manifest.md').write_text(f'# Geometry audit digest\n\nFinalized{len(files)} private files;104 source artifacts reverified unchanged. Complete manifest SHA-256 `{manifest_sha}`. Human/AI reference and complete raw CSV retain the bounded claims, corrections and unknowns. No engine/repository/frozen changes.\n')
print(json.dumps({'result': 'finalized', 'files': len(files), 'manifest_sha256': manifest_sha, 'source_artifacts_reverified': len(sources), 'classified_FIFO_stores': fifo_count, 'non_FIFO_candidate': non_fifo_count, 'reference': str(OUT / 'geometry-reference.md')}, separators=(',', ':')))
