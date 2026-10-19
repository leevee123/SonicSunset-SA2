"""Once-only source, caller and original-word selection for grouped geometry."""
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
    fields = list(dict.fromkeys(k for r in values for k in r))
    with (OUT / name).open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fields)
        w.writeheader()
        w.writerows(values)


decoder = ROOT / 'work/full-decompile/audit_odekake_pointer_abi_v1.py'
tree = ast.parse(read(decoder))
namespace = {}
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('sign', 'decode')]
exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(decoder), 'exec'), namespace)
decode = namespace['decode']
dol = read(ROOT / 'work/sa2-disc/main.dol')
mapping = json.loads(read(ROOT / 'work/dol-elf-mapping-final.json'))
assert hashlib.sha256(dol).hexdigest() == mapping['dol_sha256'] == 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'
with (ROOT / 'work/sa2.iso').open('rb') as f:
    f.seek(0x420)
    iso_base = struct.unpack('>I', f.read(4))[0]
    f.seek(iso_base)
    assert f.read(len(dol)) == dol


def offset(va):
    m = next(m for m in mapping['mappings'] if m['address'] <= va < m['address'] + m['size'])
    return m['dol_offset'] + va - m['address']


def coords(va):
    return {'va': hex(va), 'dol_offset': hex(offset(va)), 'iso_offset': hex(iso_base + offset(va))}


def word(va):
    return struct.unpack_from('>I', dol, offset(va))[0]


entries = [0x80120158, 0x8011ccf8, 0x8010afc4, 0x8010b010]
sources, native, retained, calls, ranges_out = [], [], [], [], []
views = {}
for view in ['main', 'main-sda-v1']:
    folder = ROOT / 'work/full-decompile/gekko' / view / 'export'
    catalog = {int(r['entry'], 16): r for r in rows(folder / 'functions.csv')}
    ranges = rows(folder / 'function_body_ranges.csv')
    graph = rows(folder / 'direct_calls.csv')
    views[view] = {}
    for entry in entries:
        row = catalog[entry]
        views[view][entry] = [(int(r['range_start'], 16), int(r['range_end_exclusive'], 16)) for r in ranges if int(r['entry'], 16) == entry]
        for kind in ['pseudocode', 'assembly']:
            if not row[kind + '_path']:
                continue
            path = folder / row[kind + '_path']
            data = read(path)
            assert hashlib.sha256(data).hexdigest() == row[kind + '_sha256']
            sources.append({'view': view, 'entry': hex(entry), **coords(entry), 'kind': kind, 'path': str(path), 'sha256': row[kind + '_sha256'], 'status': row['status']})
            if kind == 'assembly':
                for va, pos, opcode, asm, override in re.findall(r'^([0-9a-f]{8}) file=(0x[0-9a-f]+) ([0-9a-f]{8}) (.*?) flow=(.*?)$', data.decode(), re.M):
                    va = int(va, 16)
                    assert int(pos, 16) == offset(va) and int(opcode, 16) == word(va)
                    retained.append({'view': view, 'entry': hex(entry), **coords(va), 'word': opcode, 'assembly': asm, 'override': override})
        for edge in graph:
            if int(edge['caller_entry'], 16) in entries and int(edge['caller_entry'], 16) == entry or int(edge['target'], 16) == entry == 0x80120158:
                va = int(edge['call_site'], 16)
                ins = decode(word(va), va)
                assert ins.get('target') == int(edge['target'], 16) and ins.get('link')
                calls.append({'view': view, **edge, **coords(va), 'word': hex(word(va))})
for entry in entries:
    a, b = views['main'][entry], views['main-sda-v1'][entry]
    assert a == b and a
    if entry in [0x8010afc4, 0x8010b010]:
        for last in range(entry, entry + 128, 4):
            if word(last) == 0x4e800020:
                a = [(entry, last + 4)]
                break
        op = 36 if entry < 0x8010b000 else 32
        for va in range(entry, a[0][1] - 4, 4):
            w = word(va)
            assert w >> 26 == op and (w >> 16) & 31 == 11 and 25 <= (w >> 21) & 31 <= 31
    for start, end in a:
        ranges_out.append({'entry': hex(entry), 'start': hex(start), 'end_exclusive': hex(end), **coords(start), 'words': (end - start) // 4})
        for va in range(start, end, 4):
            w, ins = word(va), decode(word(va), va)
            native.append({'entry': hex(entry), **coords(va), 'word': hex(w), 'decode': ins['decoded'], 'opcode': ins['opcode'], 'field21': ins['reg_field21'], 'field16': ins['reg_field16'], 'field11': ins['reg_field11'], 'xo': ins['xo'], 'immediate_s16': ins['immediate_signed'], 'target': hex(ins['target']) if 'target' in ins else ''})
selected = [r for r in native if r['entry'] == '0x80120158' or int(r['va'], 16) in range(0x8011ce60, 0x8011ceb8) or int(r['va'], 16) in range(0x8011cf2c, 0x8011cf68) or int(r['va'], 16) in range(0x8011d0e8, 0x8011d148)]
save('source-artifacts.csv', sources)
save('function-scopes.csv', ranges_out)
save('original-words.csv', native)
save('group-caller-focus-words.csv', selected)
save('retained-assembly.csv', retained)
save('direct-calls.csv', calls)
save('input-sha256.csv', [{'path': p, 'sha256': digest} for p, digest in sorted(inputs.items())])
summary = {'result': 'passed', 'source_artifacts': len(sources), 'original_words': len(native), 'retained_ASM_rows_matched': len(retained), 'direct_call_rows': len(calls), 'function_scopes': ranges_out, 'direct_incoming_grouped_sites': sorted({r['call_site'] for r in calls if int(r['target'], 16) == 0x80120158}), 'native_execution': False, 'project_opens': 0}
(OUT / 'inspection.ai.json').write_text(json.dumps(summary, indent=2) + '\n')
(OUT / 'inspection.md').write_text('# Grouped geometry source inspection\n\nOriginal C and immutable export catalogs were reused. Original DOL/ISO bytes match the prior identity. Complete grouped-helper and caller original words, mapped coordinates, source hashes and direct calls remain in CSV; no project/native execution.\n')
print(json.dumps(summary, separators=(',', ':')))
print(json.dumps({'inner_integer_original': [{'va': r['va'], 'word': r['word'], 'decode': r['decode']} for r in native if r['entry'] == '0x80120158' and int(r['va'], 16) >= 0x8012021c and r['opcode'] != 48]}, separators=(',', ':')))
