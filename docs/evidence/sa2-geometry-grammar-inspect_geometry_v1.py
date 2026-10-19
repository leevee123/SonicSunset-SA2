"""One-run source and original-word selection, without opening a project."""
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
    path = Path(path)
    data = path.read_bytes()
    inputs[str(path)] = hashlib.sha256(data).hexdigest()
    return data


def rows(path):
    return list(csv.DictReader(read(path).decode('utf-8-sig').splitlines()))


def save(name, values):
    keys = list(dict.fromkeys(k for r in values for k in r))
    with (OUT / name).open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, keys)
        w.writeheader()
        w.writerows(values)


decoder = ROOT / 'work/full-decompile/audit_odekake_pointer_abi_v1.py'
tree = ast.parse(read(decoder))
space = {}
defs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('sign', 'decode')]
exec(compile(ast.fix_missing_locations(ast.Module(body=defs, type_ignores=[])), str(decoder), 'exec'), space)
base_decode = space['decode']
sign = space['sign']


def decode(w, va):
    r = base_decode(w, va)
    op, d, a, b, xo = (r[k] for k in ['opcode', 'reg_field21', 'reg_field16', 'reg_field11', 'xo'])
    if op in (12, 13):
        r['decoded'] = ('addic.' if op == 13 else 'addic') + f' r{d},r{a},{sign(w & 65535,16)}'
    elif op == 48:
        r['decoded'] = f'lfs f{d},{sign(w & 65535,16)}(r{a})'
    elif op == 52:
        r['decoded'] = f'stfs f{d},{sign(w & 65535,16)}(r{a})'
    elif op == 31 and xo == 104:
        r['decoded'] = f'neg r{d},r{a}'
    elif op == 31 and xo == 922:
        r['decoded'] = f'extsh r{a},r{d}'
    return r


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


core = [0x8011d594, 0x8011d6a4, 0x8011d7b4, 0x8011d91c, 0x8011fef4, 0x8011fff4, 0x80120158]
emitters = [0x80101948, 0x8011d678, 0x8011d67c, 0x8011d690, 0x8011d788, 0x8011d78c, 0x8011d7a0, 0x8011d8e0, 0x8011d8e4, 0x8011d8f4, 0x8011d908, 0x8011da04, 0x8011da08, 0x8011da1c, 0x8011ffd0, 0x8011ffd4, 0x8011ffe0, 0x80120124, 0x80120128, 0x80120138, 0x80120144]
helpers = [0x8010afc0, 0x8010afc4, 0x8010afc8, 0x8010b00c, 0x8010b010, 0x8010b014]
entries = core + emitters + helpers
sources, functions, native, retained, calls = [], [], [], [], []
catalogs, ranges = {}, {}
for view in ['main', 'main-sda-v1']:
    folder = ROOT / 'work/full-decompile/gekko' / view / 'export'
    catalog = {int(r['entry'], 16): r for r in rows(folder / 'functions.csv')}
    catalogs[view] = catalog
    ranges[view] = rows(folder / 'function_body_ranges.csv')
    graph = rows(folder / 'direct_calls.csv')
    for entry in entries:
        r = catalog[entry]
        assert int(r['canonical_file_offset'], 16) == offset(entry)
        for kind in ['pseudocode', 'assembly']:
            if not r[kind + '_path']:
                continue
            p = folder / r[kind + '_path']
            data = read(p)
            assert hashlib.sha256(data).hexdigest() == r[kind + '_sha256']
            sources.append({'view': view, 'entry': hex(entry), **coords(entry), 'kind': kind, 'path': str(p), 'sha256': r[kind + '_sha256'], 'status': r['status'], 'body_ranges': r['body_ranges']})
            if kind == 'assembly':
                for va, position, opcode, instruction, override in re.findall(r'^([0-9a-f]{8}) file=(0x[0-9a-f]+) ([0-9a-f]{8}) (.*?) flow=(.*?)$', data.decode(), re.M):
                    va = int(va, 16)
                    assert int(opcode, 16) == word(va) and int(position, 16) == offset(va)
                    retained.append({'view': view, 'entry': hex(entry), **coords(va), 'word': opcode, 'retained_assembly': instruction, 'flow_override': override})
        for edge in graph:
            if int(edge['caller_entry'], 16) == entry:
                va, target = int(edge['call_site'], 16), int(edge['target'], 16)
                ins = decode(word(va), va)
                assert ins.get('target') == target and ins.get('link')
                calls.append({'view': view, **edge, **coords(va), 'word': hex(word(va))})
for entry in entries:
    a = [(int(r['range_start'], 16), int(r['range_end_exclusive'], 16)) for r in ranges['main'] if int(r['entry'], 16) == entry]
    b = [(int(r['range_start'], 16), int(r['range_end_exclusive'], 16)) for r in ranges['main-sda-v1'] if int(r['entry'], 16) == entry]
    assert a == b and a
    if entry in helpers:
        for end in range(entry, entry + 128, 4):
            if word(end) == 0x4e800020:
                a = [(entry, end + 4)]
                break
        else:
            raise AssertionError('No bounded GPR helper return')
        opcode = 36 if entry < 0x8010b000 else 32
        for va in range(entry, a[0][1] - 4, 4):
            w = word(va)
            assert w >> 26 == opcode and ((w >> 16) & 31) == 11 and 24 <= ((w >> 21) & 31) <= 31
    count = 0
    for start, end in a:
        for va in range(start, end, 4):
            w, ins = word(va), decode(word(va), va)
            native.append({'entry': hex(entry), **coords(va), 'word': hex(w), 'decode': ins['decoded'], 'opcode': ins['opcode'], 'xo': ins['xo'], 'field21': ins['reg_field21'], 'field16': ins['reg_field16'], 'field11': ins['reg_field11'], 'immediate_s16': ins['immediate_signed'], 'target': hex(ins['target']) if 'target' in ins else ''})
            count += 1
    functions.append({'entry': hex(entry), **coords(entry), 'ranges': json.dumps([[hex(x), hex(y)] for x, y in a]), 'words': count, 'scope': 'core consumer' if entry in core else 'output emitter' if entry in emitters else 'verified GPR save/restore through return'})
structural = [r for r in native if int(r['entry'], 16) in core and (int(r['opcode']) in [12, 13, 14, 16, 21, 32, 40, 42] or (int(r['opcode']) == 31 and int(r['xo']) in [104, 922, 266]))]
save('source-artifacts.csv', sources)
save('function-scopes.csv', functions)
save('original-words.csv', native)
save('structural-original-words.csv', structural)
save('retained-assembly.csv', retained)
save('direct-calls.csv', calls)
save('input-sha256.csv', [{'path': p, 'sha256': d} for p, d in sorted(inputs.items())])
result = {'result': 'original source/word inventory passed', 'core_functions': [hex(v) for v in core], 'function_scopes': len(functions), 'source_artifacts': len(sources), 'original_words': len(native), 'retained_ASM_matched': len(retained), 'direct_call_rows': len(calls), 'missing_assembly_reason': 'Successful core functions were exported C-only; original words selected directly through matched main/SDA body ranges.', 'DOL_ISO_base': hex(iso_base), 'DOL_sha256': hashlib.sha256(dol).hexdigest(), 'decoder': 'Reused AST-selected pure bounded decoder; added local convenience labels addic/lfs/stfs/neg/extsh without modifying original helper; unknown words retained.', 'native_execution': False, 'Ghidra_project_opens': 0}
(OUT / 'inspection.ai.json').write_text(json.dumps(result, indent=2) + '\n')
(OUT / 'inspection.md').write_text('# Original geometry helper inspection\n\nMatched main/SDA body ranges and immutable C/ASM source hashes against the original DOL/ISO. Core C was read before original words; successful core functions have no retained ASM, so their complete original words are retained with a bounded convenience decoder. Unsupported words remain unclassified. No project was opened or native code executed. Full results: inspection.ai.json and complete CSV.\n')
print(json.dumps(result, separators=(',', ':')))
for entry in core:
    values = [{'va': r['va'], 'word': r['word'], 'instruction': r['decode']} for r in structural if r['entry'] == hex(entry)]
    print(json.dumps({'entry': hex(entry), 'structural': values}, separators=(',', ':')))
