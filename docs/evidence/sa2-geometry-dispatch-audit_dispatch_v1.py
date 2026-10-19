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


"""/* Collect the bounded functions' C first; retain complete matching lines
and hashes, then use original instructions only to recover dropped effects. */"""
emitters = (0x8011D594, 0x8011D6A4, 0x8011D7B4, 0x8011D91C, 0x8011FEF4, 0x8011FFF4, 0x80120158)
fifo_helpers = (0x8011D678, 0x8011D67C, 0x8011D690, 0x8011D788, 0x8011D78C, 0x8011D7A0, 0x8011D8E0, 0x8011D8E4, 0x8011D8F4, 0x8011D908, 0x8011DA04, 0x8011DA08, 0x8011DA1C, 0x8011FFD0, 0x8011FFD4, 0x8011FFE0, 0x80120124, 0x80120128, 0x80120138, 0x80120144)
entries = (0x8011CCF8, 0x8011C960, 0x8011C9AC, 0x8011C9F8, 0x8011CAAC, 0x8011CC08, 0x8011D1AC, 0x8011D2F4, 0x80100CF8, 0x80100830, 0x80100D44, 0x80101948, 0x801011D8) + emitters + fifo_helpers
views = {name: ROOT / 'work/full-decompile/gekko' / name / 'export' for name in ('main', 'main-sda-v1')}
c_lines = []
c_texts = {}
for view, folder in views.items():
    for entry in entries:
        path = folder / 'pseudocode' / f'{hex(entry)}.c'
        text = read(path).decode('utf-8')
        c_texts[view, entry] = text
        for number, line in enumerate(text.splitlines(), 1):
            if any(token in line for token in ('FUN_', 'DAT_', 'psVar', 'pfVar', 'param_3', 'param_4', 'param_5')):
                c_lines.append({'view': view, 'entry': hex(entry), 'line': number, 'text': line.strip(), 'path': str(path.relative_to(ROOT))})

decoder_path = ROOT / 'work/full-decompile/audit_odekake_pointer_abi_v1.py'
tree = ast.parse(read(decoder_path))
definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in ('sign', 'decode')]
space = {}
exec(compile(ast.fix_missing_locations(ast.Module(body=definitions, type_ignores=[])), str(decoder_path), 'exec'), space)
decode = space['decode']
dol = read(ROOT / 'work/sa2-disc/main.dol')
mapping = json.loads(read(ROOT / 'work/dol-elf-mapping-final.json'))
assert hashlib.sha256(dol).hexdigest() == mapping['dol_sha256'] == 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'


def offset(address):
    segment = next(row for row in mapping['mappings'] if row['address'] <= address < row['address'] + row['size'])
    return segment['dol_offset'] + address - segment['address']


def word(address):
    return struct.unpack_from('>I', dol, offset(address))[0]


"""/* Require identical primary/SDA body ranges and compare every retained ASM
word and offset. Preserve unsupported instructions without FP interpretation. */"""
ranges = {view: rows(folder / 'function_body_ranges.csv') for view, folder in views.items()}
graphs = {view: rows(folder / 'direct_calls.csv') for view, folder in views.items()}
computed = {view: rows(folder / 'computed_calls.csv') for view, folder in views.items()}
raw = []
function_rows = []
calls = []
computed_rows = []
asm_compared = 0
for entry in entries:
    spans = {}
    retained = {}
    for view, folder in views.items():
        spans[view] = [(int(row['range_start'], 16), int(row['range_end_exclusive'], 16)) for row in ranges[view] if int(row['entry'], 16) == entry]
        path = folder / 'assembly' / f'{hex(entry)}.asm'
        if path.exists():
            for address, position, value, text in re.findall(r'^([0-9a-f]{8}) file=(0x[0-9a-f]+) ([0-9a-f]{8}) (.*?) flow=', read(path).decode('utf-8'), re.M):
                address = int(address, 16)
                assert int(position, 16) == offset(address)
                assert int(value, 16) == word(address)
                retained[address] = text
                asm_compared += 1
    assert spans['main'] == spans['main-sda-v1'] and spans['main'], hex(entry)
    addresses = sorted({address for start, end in spans['main'] for address in range(start, end, 4)})
    for address in addresses:
        value = word(address)
        decoded = decode(value, address)
        assert decoded['opcode'] == value >> 26
        raw.append({'entry': hex(entry), 'va': hex(address), 'dol_file_offset': hex(offset(address)), 'iso_file_offset': hex(0x1E700 + offset(address)), 'word': f'{value:08x}', 'integer_decode': decoded['decoded'], 'integer_detail': json.dumps(decoded, separators=(',', ':')), 'retained_ASM': retained.get(address, ''), 'opcode': value >> 26, 'field21': (value >> 21) & 31, 'field16': (value >> 16) & 31, 'field11': (value >> 11) & 31, 'immediate_signed': space['sign'](value & 0xFFFF, 16)})
    function_rows.append({'entry': hex(entry), 'dol_file_offset': hex(offset(entry)), 'iso_file_offset': hex(0x1E700 + offset(entry)), 'original_words': len(addresses), 'ranges': json.dumps([{'start': hex(a), 'end_exclusive': hex(b)} for a, b in spans['main']])})
    for view in views:
        calls.extend({'view': view, **row} for row in graphs[view] if int(row['caller_entry'], 16) == entry)
        computed_rows.extend({'view': view, **row} for row in computed[view] if int(row['caller_entry'], 16) == entry)

"""/* Track simple integer base construction within each bounded function to
identify direct FIFO stores. Calls invalidate volatile constants. This is not
general execution or MMIO alias closure; complete original rows remain available. */"""
fifo = []
for entry in entries:
    constants = {0: 0}
    ordinal = 0
    for row in [row for row in raw if int(row['entry'], 16) == entry]:
        value = int(row['word'], 16)
        opcode, rs, ra = value >> 26, (value >> 21) & 31, (value >> 16) & 31
        immediate = space['sign'](value & 0xFFFF, 16)
        if opcode in (36, 38, 44, 52, 54) and ra in constants:
            target = (constants[ra] + immediate) & 0xFFFFFFFF
            if target == 0xCC008000:
                ordinal += 1
                fifo.append({**row, 'FIFO_ordinal_in_function': ordinal, 'store': {36: 'stw', 38: 'stb', 44: 'sth', 52: 'stfs', 54: 'stfd'}[opcode], 'source_register': ('f' if opcode in (52, 54) else 'r') + str(rs), 'bytes': {36: 4, 38: 1, 44: 2, 52: 4, 54: 8}[opcode], 'target': hex(target)})
        if opcode in (14, 15):
            base = 0 if ra == 0 else constants.get(ra)
            if base is None:
                constants.pop(rs, None)
            else:
                constants[rs] = (base + (immediate << (16 if opcode == 15 else 0))) & 0xFFFFFFFF
        elif opcode == 24:
            if rs in constants:
                constants[ra] = constants[rs] | (value & 0xFFFF)
            else:
                constants.pop(ra, None)
        elif opcode == 18 and value & 1:
            for reg in (0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12):
                constants.pop(reg, None)
        elif opcode not in (36, 38, 44, 52, 54):
            for reg in json.loads(row['integer_detail'])['writes']:
                constants.pop(reg, None)

save('C-first-feature-lines.csv', c_lines)
save('original-words.csv', raw)
save('function-ranges.csv', function_rows)
save('direct-calls.csv', calls)
if computed_rows:
    save('computed-calls.csv', computed_rows)
save('direct-FIFO-stores.csv', fifo)
save('input-source-hashes.csv', [{'path': path, 'sha256': sha} for path, sha in sorted(inputs.items())])
result = {'version': 1, 'scope': 'bounded40 functions: dispatcher,7 emitters,20 local FIFO helpers,12 state/attribute/flush helpers; no caller/reset/module/FP closure', 'function_count': len(entries), 'original_words': len(raw), 'retained_ASM_rows_compared': asm_compared, 'direct_call_rows_two_views': len(calls), 'computed_call_rows_two_views': len(computed_rows), 'identified_direct_FIFO_store_rows': len(fifo), 'input_sources': len(inputs), 'DOL_sha256': hashlib.sha256(dol).hexdigest(), 'FIFO_helpers': [{'entry': hex(entry), 'stores': [(row['store'], row['source_register']) for row in fifo if int(row['entry'], 16) == entry]} for entry in fifo_helpers], 'limitations': ['C and graph outputs remain generated analyses.', 'Direct FIFO-store tracking only follows simple local constant bases; all original words retained.', 'No topology, floating-point, cache-lifetime, allocation or retail-execution claim.']}
(OUT / 'original-audit.ai.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
(OUT / 'original-audit.md').write_text(f"# Geometry original-word audit\n\n{len(entries)} bounded functions, {len(raw)} complete original words; {asm_compared} retained ASM rows agree with original words and VA/DOL offsets. Complete C feature rows, graphs, raw words, local FIFO stores and {len(inputs)} input hashes are retained. No program/project/native execution or mutations.\n", encoding='utf-8')
print(json.dumps({key: result[key] for key in ('function_count', 'original_words', 'retained_ASM_rows_compared', 'identified_direct_FIFO_store_rows', 'input_sources')}, separators=(',', ':')))
for item in result['FIFO_helpers']:
    if item['stores']:
        print(item['entry'], item['stores'])
