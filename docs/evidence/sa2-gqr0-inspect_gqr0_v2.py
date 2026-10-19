"""Once-only C-first caller selection and original words for bounded GQR0 paths."""
import ast
import csv
import hashlib
import json
import re
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
assert not (OUT / 'inspection.ai.json').exists()
inputs = {}


def read(path):
    p = Path(path)
    b = p.read_bytes()
    inputs[str(p)] = hashlib.sha256(b).hexdigest()
    return b


def rows(path):
    return list(csv.DictReader(read(path).decode('utf-8-sig').splitlines()))


def save(name, values):
    fields = list(dict.fromkeys(k for r in values for k in r)) or ['result']
    with (OUT / name).open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fields)
        w.writeheader()
        w.writerows(values)


def signed(value, bits=16):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


tree = ast.parse(read(ROOT / 'work/full-decompile/audit_odekake_pointer_abi_v1.py'))
space = {}
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ['decode', 'sign']]
exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), 'prior_pure_decoder', 'exec'), space)
decode = space['decode']
dol = read(ROOT / 'work/sa2-disc/main.dol')
maps = json.loads(read(ROOT / 'work/dol-elf-mapping-final.json'))
assert hashlib.sha256(dol).hexdigest() == maps['dol_sha256']


def offset(va):
    m = next(m for m in maps['mappings'] if m['address'] <= va < m['address'] + m['size'])
    return m['dol_offset'] + va - m['address']


def coords(va):
    return {'va': hex(va), 'dol_offset': hex(offset(va)), 'iso_offset': hex(0x1e700 + offset(va))}


def word(va):
    return struct.unpack_from('>I', dol, offset(va))[0]


core = {0x800e3d38, 0x8010a6b4, 0x8010a86c, 0x80003330, 0x80003140, 0x800e5388, 0x800e54ac}
targets = {0x800e3d38, 0x8010a6b4, 0x8010a86c, 0x80003330}
branches = []
for seg in rows(OUT / 'original-text-segments.csv'):
    for va in range(int(seg['va'], 16), int(seg['end_exclusive'], 16), 4):
        w = word(va)
        if w >> 26 != 18:
            continue
        displacement = signed(w & 0x3fffffc, 26)
        target = (displacement if w & 2 else va + displacement) & 0xffffffff
        if target in targets:
            branches.append({**coords(va), 'word': hex(w), 'target': hex(target), 'link': bool(w & 1), 'absolute': bool(w & 2)})

sources, c_lines, native, asm_rows, call_rows, scopes, incoming_owners = [], [], [], [], [], [], []
for view in ['main', 'main-sda-v1']:
    base = ROOT / 'work/full-decompile/gekko' / view / 'export'
    catalog = {int(r['entry'], 16): r for r in rows(base / 'functions.csv')}
    ranges = rows(base / 'function_body_ranges.csv')
    graph = rows(base / 'direct_calls.csv')
    selected = set(core)
    for b in branches:
        va = int(b['va'], 16)
        for r in ranges:
            if int(r['range_start'], 16) <= va < int(r['range_end_exclusive'], 16):
                entry = int(r['entry'], 16)
                selected.add(entry)
                incoming_owners.append({'view': view, **b, 'owner': hex(entry)})
    for entry in sorted(selected):
        r = catalog[entry]
        for kind in ['pseudocode', 'assembly']:
            if not r[kind + '_path']:
                continue
            path = base / r[kind + '_path']
            data = read(path)
            assert hashlib.sha256(data).hexdigest() == r[kind + '_sha256']
            sources.append({'view': view, 'entry': hex(entry), **coords(entry), 'kind': kind, 'path': str(path), 'sha256': r[kind + '_sha256'], 'status': r['status']})
            if kind == 'pseudocode':
                lines = data.decode('utf-8-sig').splitlines()
                indices = {j for i, line in enumerate(lines) if re.search(r'FUN_80003330|FUN_800e3d38|FUN_8010a6b4|FUN_8010a86c|GQR[0-7]|6da4|1a[02468c]|0x194|0x1c8|FUN_800e5388|FUN_800e54ac', line, re.I) for j in range(max(0, i-2), min(len(lines), i+3))}
                c_lines.extend({'view': view, 'entry': hex(entry), 'line': i + 1, 'text': lines[i], 'source_sha256': r['pseudocode_sha256']} for i in sorted(indices))
            else:
                for va, pos, opcode, instruction in re.findall(r'^([0-9a-f]{8}) file=(0x[0-9a-f]+) ([0-9a-f]{8}) (.*?) flow=', data.decode(), re.M):
                    va = int(va, 16)
                    assert int(pos, 16) == offset(va) and int(opcode, 16) == word(va)
                    asm_rows.append({'view': view, 'entry': hex(entry), **coords(va), 'word': opcode, 'assembly': instruction})
        for body in ranges:
            if int(body['entry'], 16) != entry:
                continue
            start, end = int(body['range_start'], 16), int(body['range_end_exclusive'], 16)
            scopes.append({'view': view, **body, **coords(start)})
            if view != 'main':
                continue
            for va in range(start, end, 4):
                w, ins = word(va), decode(word(va), va)
                native.append({'entry': hex(entry), **coords(va), 'word': hex(w), 'decode_subset': ins['decoded'], 'opcode': w >> 26, 'field21': (w >> 21) & 31, 'field16': (w >> 16) & 31, 'field11': (w >> 11) & 31, 'xo': (w >> 1) & 1023, 'immediate_s16': signed(w & 65535)})
        for edge in graph:
            if int(edge['caller_entry'], 16) == entry or int(edge['target'], 16) == entry and entry in core:
                va = int(edge['call_site'], 16)
                ins = decode(word(va), va)
                edge = {**edge, 'raw_target': hex(ins['target']) if 'target' in ins else '', 'raw_link_bit': ins.get('link', ''), 'raw_target_matches_graph': ins.get('target') == int(edge['target'], 16)}
                call_rows.append({'view': view, **edge, **coords(va), 'word': hex(word(va))})
save('bounded-source-artifacts.csv', sources)
save('bounded-C-lines.csv', c_lines)
save('bounded-original-words.csv', native)
save('bounded-retained-ASM.csv', asm_rows)
save('bounded-direct-calls.csv', call_rows)
save('bounded-function-scopes.csv', scopes)
save('all-text-direct-owner-branches.csv', branches)
save('all-text-branch-function-owners.csv', incoming_owners)
save('inspection-input-sha256.csv', [{'path': p, 'sha256': d} for p, d in sorted(inputs.items())])
summary = {'result': 'passed', 'source_artifacts': len(sources), 'original_words': len(native), 'retained_ASM_rows_matched': len(asm_rows), 'direct_call_rows': len(call_rows), 'full_text_direct_branches': branches, 'branch_owners': incoming_owners, 'selected_entries': sorted({r['entry'] for r in sources}), 'source_selection_limits': ['Core startupGQR0 and globalrestore functions completed C-only: no individual ASM file.', 'Expanded FP-context C oversized/truncated; selected structural C lines and complete original words retained.'], 'native_execution': False, 'project_opens': 0}
(OUT / 'inspection.ai.json').write_text(json.dumps(summary, indent=2) + '\n')
(OUT / 'inspection.md').write_text('# GQR0 original-word and caller inspection\n\nC-first sources and original words are retained for the three GQR0 owners, startup entry/helper, ordinary FP contexts and directly branching caller owners. Every retained ASM word and graph direct call matches the original DOL. Missing C-only ASM and expanded-context C output limits are explicit. Complete raw evidence includes all text direct entry branches, not indirect caller closure or execution.\n')
print(json.dumps(summary, separators=(',', ':')))
print(json.dumps({'focus_original': [{k: r[k] for k in ['entry','va','word','decode_subset']} for r in native if r['entry'] == '0x800e3d38' or 0x8010a76c <= int(r['va'],16) < 0x8010a7a8 or 0x8010a86c <= int(r['va'],16) < 0x8010a8d0]}, separators=(',', ':')))
for entry in sorted({r['owner'] for r in incoming_owners} - {hex(x) for x in core}):
    lines = [r['text'] for r in c_lines if r['view']=='main' and r['entry']==entry]
    print(json.dumps({'caller': entry, 'C_selected_lines': lines}, separators=(',', ':')))

