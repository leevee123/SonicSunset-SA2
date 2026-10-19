"""Once-only original selector/value guards, context inventory and bounded C selection."""
import collections
import csv
import hashlib
import json
import re
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
assert not (OUT / 'validation.ai.json').exists()


def rows(path):
    with Path(path).open(newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(name, values):
    fields = list(dict.fromkeys(k for r in values for k in r)) or ['result']
    with (OUT / name).open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fields)
        w.writeheader()
        w.writerows(values)


native = rows(OUT / 'bounded-original-words.csv')
by_va = {int(r['va'], 16): r for r in native}
word = lambda va: int(by_va[va]['word'], 16)
assert word(0x800e3d58) == 0x38600000 and word(0x800e3d5c) == 0x7c70e3a6
assert word(0x8010a788) == 0x7e90e2a6 and word(0x8010a8ac) == 0x7e90e3a6
assert word(0x8010a8a8) >> 26 == 46 and (word(0x8010a8a8) >> 21) & 31 == 20 and word(0x8010a8a8) & 65535 == 0x2fc
save_store = [r for r in native if r['entry'] == '0x8010a6b4' and int(r['opcode']) == 47 and int(r['field21']) == 20 and int(r['field16']) == 2 and int(r['immediate_s16']) == 0x2fc]
assert len(save_store) == 1
assert word(0x8010a86c) == 0x3c40802d and word(0x8010a870) == 0x60426aa8
snapshot_base = ((word(0x8010a86c) & 65535) << 16) | (word(0x8010a870) & 65535)
snapshot_slot = snapshot_base + 0x2fc
assert snapshot_slot == 0x802d6da4
base_constructions = []
for r in native:
    va, w = int(r['va'], 16), int(r['word'], 16)
    if w >> 26 == 15 and (w >> 21) & 31 == 2 and (w >> 16) & 31 == 0 and va + 4 in by_va:
        nextw = word(va + 4)
        if nextw >> 26 == 24 and (nextw >> 21) & 31 == 2 and (nextw >> 16) & 31 == 2:
            base = ((w & 65535) << 16) | (nextw & 65535)
            base_constructions.append({'entry': r['entry'], 'construction_va': r['va'], 'second_va': hex(va+4), 'r2_constant': hex(base), 'base_plus_2FC': hex(base+0x2fc)})
owners = rows(OUT / 'GQR-access-owners.csv')
context_summary = []
for entry in sorted({r['entry'] for r in owners if r['entry']}):
    values = [r for r in owners if r['view'] == 'main' and r['entry'] == entry]
    context_summary.append({'entry': entry, 'GQR_read_ids': ';'.join(str(r['GQR']) for r in values if r['access']=='read_mfspr'), 'GQR_write_ids': ';'.join(str(r['GQR']) for r in values if r['access']=='write_mtspr'), 'sites': ';'.join(r['va'] for r in values)})

# Read other architectural-context owners' generated C before selecting their raw words.
prior_sources = rows(OUT / 'owner-source-artifacts.csv')
c_selected = []
for r in prior_sources:
    if r['kind'] != 'pseudocode' or r['view'] != 'main':
        continue
    assert sha(r['path']) == r['sha256']
    text = Path(r['path']).read_text(encoding='utf-8-sig')
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.search(r'GQR[0-7]|0x1a[0-9a-f]|0x1b[0-9a-f]|FUN_800e53|FUN_800e54|FUN_8010a', line, re.I):
            c_selected.append({'entry': r['entry'], 'path': r['path'], 'source_sha256': r['sha256'], 'line': i+1, 'text': line})
all_sources = rows(OUT / 'bounded-source-artifacts.csv') + prior_sources
for r in all_sources:
    assert sha(r['path']) == r['sha256']
graph = rows(OUT / 'bounded-direct-calls.csv')
exceptions = [r for r in graph if r['raw_target_matches_graph'] != 'True' or r['raw_link_bit'] != 'True']
save('r2-snapshot-base-constructions.csv', base_constructions)
save('snapshot-GQR0-save-store.csv', save_store)
save('all-GQR-owner-summary.csv', context_summary)
save('additional-context-C-lines.csv', c_selected)
save('graph-versus-native-classification-exceptions.csv', exceptions)
save('value-evidence-sites.csv', [by_va[va] for va in [0x80003144,0x80003340,0x800e3d58,0x800e3d5c,0x8010a788,0x8010a86c,0x8010a870,0x8010a8a8,0x8010a8ac]] + save_store)
mapping = json.loads((ROOT / 'work/dol-elf-mapping-final.json').read_text())
slot_file_mappings = [m for m in mapping['mappings'] if m['address'] <= snapshot_slot < m['address']+m['size']]
assert not slot_file_mappings
slot_in_bss = mapping['bss_address'] <= snapshot_slot < mapping['bss_address'] + mapping['bss_size']
assert slot_in_bss
summary = {'result': 'passed', 'startup_value': 0, 'startup_write_site': '0x800e3d5c', 'save_read_site': '0x8010a788', 'save_store_site': save_store[0]['va'], 'snapshot_restore_base': hex(snapshot_base), 'snapshot_slot': hex(snapshot_slot), 'snapshot_slot_original_file_offset': None, 'snapshot_slot_in_DOL_BSS': slot_in_bss, 'restore_load_site': '0x8010a8a8', 'restore_write_site': '0x8010a8ac', 'restore_value': 'memory word at802D6DA4, not a literal zero', 'r2_base_constructions': base_constructions, 'GQR_owner_summary': context_summary, 'graph_rows': len(graph), 'graph_classification_exceptions': len(exceptions), 'source_artifact_rows_reverified': len(all_sources), 'distinct_source_files_reverified': len({r['path'] for r in all_sources}), 'architectural_zero_interpretation': {'st_type': 0,'st_scale':0,'ld_type':0,'ld_scale':0,'type_reference':'pinnedGekko.h QUANTIZE_FLOAT=0; conditional register decoding only'}, 'live_gameplay_GQR0_proven': False, 'native_execution': False, 'project_opens': 0}
(OUT / 'validation.ai.json').write_text(json.dumps(summary, indent=2)+'\n')
(OUT / 'validation.md').write_text('# GQR0 value validation\n\nOriginal word guards prove the startup writer receives literal zero. A separate global register snapshot reads GQR0 and saves it to the BSS snapshot slot802D6DA4; its restore writer loads that memory word rather than a literal. Source hashes and graph/native transfer distinctions are preserved. This does not establish successful startup execution, snapshot integrity, whole-carrier writer closure or live gameplay GQR0. Complete raw details are in the AI twin/CSV.\n')
print(json.dumps(summary,separators=(',',':')))
print(json.dumps({'save_prefix':[{k:r[k] for k in ['va','word','decode_subset']} for r in native if r['entry']=='0x8010a6b4'][:8],'context_C_selected':c_selected,'graph_exceptions':exceptions},separators=(',',':')))
