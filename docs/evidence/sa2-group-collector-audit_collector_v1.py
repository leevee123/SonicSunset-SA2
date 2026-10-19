import ast
import csv
import hashlib
import json
import re
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
inputs = {}


def read(path):
    path = Path(path)
    data = path.read_bytes()
    inputs[str(path.relative_to(ROOT))] = hashlib.sha256(data).hexdigest()
    return data


def rows(path):
    return list(csv.DictReader(read(path).decode('utf-8-sig').splitlines()))


def save(name, values, fields=None):
    with (OUT / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields or list(values[0]))
        writer.writeheader()
        writer.writerows(values)


"""/* Read bounded C first. Preserve raw original words only after the C has
identified collector, helper-call and reset questions. No database is opened. */"""
entries = (0x8011CCF8, 0x80120158, 0x8011C754, 0x8011C76C, 0x8011C85C, 0x8011C628, 0x8011CAAC, 0x8011CC08, 0x8011C9F8, 0x8011D1AC, 0x8010AFB0, 0x8010AFFC)
views = {view: ROOT / 'work/full-decompile/gekko' / view / 'export' for view in ('main', 'main-sda-v1')}
c_lines = []
for view, folder in views.items():
    for entry in entries:
        path = folder / 'pseudocode' / f'{hex(entry)}.c'
        for number, line in enumerate(read(path).decode('utf-8').splitlines(), 1):
            if line.strip():
                c_lines.append({'view': view, 'entry': hex(entry), 'line': number, 'text': line.strip(), 'path': str(path.relative_to(ROOT))})

decoder_path = ROOT / 'work/full-decompile/audit_odekake_pointer_abi_v1.py'
tree = ast.parse(read(decoder_path))
definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in ('sign', 'decode')]
namespace = {}
exec(compile(ast.fix_missing_locations(ast.Module(body=definitions, type_ignores=[])), str(decoder_path), 'exec'), namespace)
decode = namespace['decode']
dol = read(ROOT / 'work/sa2-disc/main.dol')
mapping = json.loads(read(ROOT / 'work/dol-elf-mapping-final.json'))
assert hashlib.sha256(dol).hexdigest() == mapping['dol_sha256'] == 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'


def offset(address):
    segment = next(item for item in mapping['mappings'] if item['address'] <= address < item['address'] + item['size'])
    return segment['dol_offset'] + address - segment['address']


def word(address):
    return struct.unpack_from('>I', dol, offset(address))[0]


"""/* Audit equal frozen body ranges and all retained ASM rows. The two shared
save/restore families are checked through their actual13-word suffixes. */"""
ranges = {view: rows(folder / 'function_body_ranges.csv') for view, folder in views.items()}
graphs = {view: rows(folder / 'direct_calls.csv') for view, folder in views.items()}
computed = {view: rows(folder / 'computed_calls.csv') for view, folder in views.items()}
raw = []
function_rows = []
calls = []
computed_rows = []
asm_count = 0
for entry in entries:
    spans = {}
    asm = {}
    for view, folder in views.items():
        spans[view] = [(int(row['range_start'], 16), int(row['range_end_exclusive'], 16)) for row in ranges[view] if int(row['entry'], 16) == entry]
        path = folder / 'assembly' / f'{hex(entry)}.asm'
        if path.exists():
            for address, position, value, text in re.findall(r'^([0-9a-f]{8}) file=(0x[0-9a-f]+) ([0-9a-f]{8}) (.*?) flow=', read(path).decode('utf-8'), re.M):
                address = int(address, 16)
                assert offset(address) == int(position, 16) and word(address) == int(value, 16)
                asm[address] = text
                asm_count += 1
    assert spans['main'] == spans['main-sda-v1'] and spans['main']
    selected = spans['main']
    if entry in (0x8010AFB0, 0x8010AFFC):
        selected = [(entry, entry + 13 * 4)]
        for index in range(12):
            value = word(entry + index * 4)
            assert (value >> 26, (value >> 21) & 31, (value >> 16) & 31) == (36 if entry == 0x8010AFB0 else 32, 20 + index, 11)
        assert word(entry + 48) == 0x4E800020
    count = 0
    for start, end in selected:
        for address in range(start, end, 4):
            value = word(address)
            detail = decode(value, address)
            assert detail['opcode'] == value >> 26
            raw.append({'entry': hex(entry), 'va': hex(address), 'dol_file_offset': hex(offset(address)), 'iso_file_offset': hex(0x1E700 + offset(address)), 'word': f'{value:08x}', 'integer_decode': detail['decoded'], 'integer_detail': json.dumps(detail, separators=(',', ':')), 'retained_ASM': asm.get(address, ''), 'opcode': value >> 26, 'field21': (value >> 21) & 31, 'field16': (value >> 16) & 31, 'field11': (value >> 11) & 31, 'immediate_signed': namespace['sign'](value & 0xFFFF, 16)})
            count += 1
    function_rows.append({'entry': hex(entry), 'dol_file_offset': hex(offset(entry)), 'iso_file_offset': hex(0x1E700 + offset(entry)), 'ranges': json.dumps([[hex(a), hex(b)] for a, b in selected]), 'original_words': count})
    for view in views:
        calls.extend({'view': view, **row} for row in graphs[view] if int(row['caller_entry'], 16) == entry)
        computed_rows.extend({'view': view, **row} for row in computed[view] if int(row['caller_entry'], 16) == entry)

save('C-first-lines.csv', c_lines)
save('original-words.csv', raw)
save('function-ranges.csv', function_rows)
save('direct-calls.csv', calls)
if computed_rows:
    save('computed-calls.csv', computed_rows)
save('input-source-hashes.csv', [{'path': path, 'sha256': sha} for path, sha in sorted(inputs.items())])
result = {'functions': len(entries), 'original_words': len(raw), 'retained_ASM_rows_compared': asm_count, 'direct_call_rows_two_views': len(calls), 'computed_call_rows_two_views': len(computed_rows), 'source_hashes': len(inputs), 'DOL_sha256': hashlib.sha256(dol).hexdigest(), 'scope': 'collector, grouped helper,4 state handlers,2 dispatch-state helpers,grouped setup/thunk, shared register save/restore suffixes; no GPU/state-callee closure'}
(OUT / 'original-audit.ai.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
(OUT / 'original-audit.md').write_text(f"# Group collector original-word audit\n\n{len(entries)} bounded scopes, {len(raw)} original words, {asm_count} retained ASM rows checked against original bytes and file offsets; {len(inputs)} source hashes retained. Full raw CSV remains complete; no database or native execution.\n", encoding='utf-8')
print(json.dumps(result, separators=(',', ':')))
for row in raw:
    address = int(row['va'], 16)
    if 0x8011CE68 <= address < 0x8011CF74 or 0x8011D0E0 <= address < 0x8011D188:
        print(row['va'], row['word'], row['retained_ASM'] or row['integer_decode'])
