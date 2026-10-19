import ast
import csv
import hashlib
import json
import re
import struct
from pathlib import Path

SOURCE_OUT = Path(__file__).resolve().parent
ROOT = SOURCE_OUT.parents[1]
OUT = SOURCE_OUT / 'word-audit-v2'
OUT.mkdir(exist_ok=False)
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


"""/* Reuse only the frozen bounded integer decoder's pure function definitions.
Do not execute the older audit's top-level code or modify its artifacts. */"""
decoder = ROOT / 'work/full-decompile/audit_odekake_pointer_abi_v1.py'
tree = ast.parse(read(decoder))
definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in ('sign', 'decode')]
space = {}
exec(compile(ast.fix_missing_locations(ast.Module(body=definitions, type_ignores=[])), str(decoder), 'exec'), space)
decode = space['decode']
dol = read(ROOT / 'work/sa2-disc/main.dol')
mapping = json.loads(read(ROOT / 'work/dol-elf-mapping-final.json'))
assert hashlib.sha256(dol).hexdigest() == mapping['dol_sha256'] == 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'


def offset(address):
    segment = next(item for item in mapping['mappings'] if item['address'] <= address < item['address'] + item['size'])
    return segment['dol_offset'] + address - segment['address']


def word(address):
    return struct.unpack_from('>I', dol, offset(address))[0]


def original(address, owner='', text=''):
    value = word(address)
    position = offset(address)
    return {'owner': owner, 'va': hex(address), 'dol_file_offset': hex(position), 'iso_file_offset': hex(0x1E700 + position), 'word': f'{value:08x}', 'decode': decode(value, address), 'retained_asm': text}


"""/* Verify DOL header mappings and scan every original text word for the exact
counter displacement, table low-half materialization and interpreter branch target.
These are explicit instruction forms, not an alias-completeness proof. */"""
header = []
text_ranges = []
for kind, count, offset_base, address_base, size_base in [('text', 7, 0, 0x48, 0x90), ('data', 11, 0x1C, 0x64, 0xAC)]:
    for index in range(count):
        position, address, size = (struct.unpack_from('>I', dol, start + 4 * index)[0] for start in (offset_base, address_base, size_base))
        if not size:
            continue
        expected = next(row for row in mapping['mappings'] if row['address'] == address)
        assert expected['dol_offset'] == position and expected['size'] == size
        assert hashlib.sha256(dol[position:position + size]).hexdigest() == expected['sha256']
        header.append({'kind': kind, 'index': index, 'va': hex(address), 'end_exclusive': hex(address + size), 'dol_file_offset': hex(position), 'iso_file_offset': hex(0x1E700 + position), 'size': size, 'sha256': expected['sha256']})
        if kind == 'text':
            text_ranges.append((address, address + size))
bss_start, bss_size = struct.unpack_from('>II', dol, 0xD8)
assert (bss_start, bss_size) == (mapping['bss_address'], mapping['bss_size'])

scan = []
branch_rows = []
text_count = 0
for start, end in text_ranges:
    for address in range(start, end, 4):
        text_count += 1
        value = word(address)
        opcode = value >> 26
        ra = (value >> 16) & 31
        kind = []
        if ra == 13 and (value & 0xFFFF) == 0x8E34 and opcode in (12, 13, 14, 15, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55):
            kind.append('exact_counter_sda_displacement')
        if (value & 0xFFFF) == 0x7A58 and opcode in (14, 24, 25):
            kind.append('table_low_half_candidate')
        if opcode == 18:
            target = space['sign'](value & 0x3FFFFFC, 26)
            if not value & 2:
                target += address
            target &= 0xFFFFFFFF
            if target == 0x8011CCF8:
                row = original(address)
                row.update(target=hex(target), absolute=bool(value & 2), link=bool(value & 1))
                branch_rows.append(row)
        if kind:
            row = original(address)
            row['kind'] = '|'.join(kind)
            scan.append(row)

literal_rows = []
for position in range(0, len(dol) - 3, 4):
    value = struct.unpack_from('>I', dol, position)[0]
    if value not in (0x80357A58, 0x803AE0F4, 0x8011CCF8):
        continue
    candidates = [row['address'] + position - row['dol_offset'] for row in mapping['mappings'] if row['dol_offset'] <= position < row['dol_offset'] + row['size']]
    literal_rows.append({'dol_file_offset': hex(position), 'iso_file_offset': hex(0x1E700 + position), 'va': hex(candidates[0]) if candidates else '', 'literal_word': hex(value)})

"""/* Retain complete original words for the bounded interpreter, wrappers and
provider path. Compare retained ASM words and offsets wherever those files exist. */"""
views = {name: ROOT / 'work/full-decompile/gekko' / name / 'export' for name in ('main', 'main-sda-v1')}
body_ranges = {view: rows(folder / 'function_body_ranges.csv') for view, folder in views.items()}
graphs = {view: rows(folder / 'direct_calls.csv') for view, folder in views.items()}
entries = (0x8011CCF8, 0x8011D2F4, 0x8011D410, 0x8011D414, 0x8011D484, 0x8011D4EC, 0x8011D554, 0x80120584, 0x80121764, 0x801217B0, 0x8011867C, 0x801199B0, 0x8010AFB0, 0x8010AFFC)
raw = []
functions = []
calls = []
asm_compared = 0
for entry in entries:
    spans = {}
    asm = {}
    for view, folder in views.items():
        read(folder / 'pseudocode' / f'{hex(entry)}.c')
        spans[view] = [(int(row['range_start'], 16), int(row['range_end_exclusive'], 16)) for row in body_ranges[view] if int(row['entry'], 16) == entry]
        path = folder / 'assembly' / f'{hex(entry)}.asm'
        if path.exists():
            for address, position, value, text in re.findall(r'^([0-9a-f]{8}) file=(0x[0-9a-f]+) ([0-9a-f]{8}) (.*?) flow=', read(path).decode('utf-8'), re.M):
                address = int(address, 16)
                assert int(position, 16) == offset(address)
                assert int(value, 16) == word(address)
                asm[address] = text
                asm_compared += 1
    assert spans['main'] == spans['main-sda-v1'] and spans['main']
    selected = spans['main']
    if entry in (0x8010AFB0, 0x8010AFFC):
        selected = [(entry, entry + 13 * 4)]
        assert word(entry + 12 * 4) == 0x4E800020
        op = 36 if entry == 0x8010AFB0 else 32
        for index in range(12):
            value = word(entry + 4 * index)
            assert (value >> 26, (value >> 21) & 31, (value >> 16) & 31) == (op, 20 + index, 11)
    count = 0
    for start, end in selected:
        for address in range(start, end, 4):
            raw.append(original(address, hex(entry), asm.get(address, '')))
            count += 1
    functions.append({'entry': hex(entry), 'dol_file_offset': hex(offset(entry)), 'iso_file_offset': hex(0x1E700 + offset(entry)), 'selected_ranges': [{'start': hex(a), 'end_exclusive': hex(b)} for a, b in selected], 'original_words': count, 'range_rule': 'audited GPR20..31 save/restore through return' if entry in (0x8010AFB0, 0x8010AFFC) else 'identical exported primary and SDA body ranges'})
    for view, values in graphs.items():
        calls.extend({'view': view, **row} for row in values if int(row['caller_entry'], 16) == entry)

save('original-DOL-segments.csv', header)
save('all-text-explicit-cache-references.csv', scan)
save('all-text-interpreter-branches.csv', branch_rows)
save('aligned-DOL-cache-literals.csv', literal_rows, ['dol_file_offset', 'iso_file_offset', 'va', 'literal_word'])
save('bounded-original-words.csv', raw)
save('bounded-direct-calls.csv', calls)
save('word-audit-source-hashes.csv', [{'path': path, 'sha256': sha} for path, sha in sorted(inputs.items())])
result = {
    'version': 2, 'DOL_sha256': hashlib.sha256(dol).hexdigest(),
    'text_words_scanned': text_count, 'explicit_reference_rows': len(scan),
    'counter_displacement_rows': sum('counter_sda' in row['kind'] for row in scan),
    'table_low_half_candidates': sum('table_low' in row['kind'] for row in scan),
    'direct_interpreter_branch_rows': len(branch_rows), 'aligned_literal_rows': len(literal_rows),
    'bounded_original_words': len(raw), 'retained_ASM_rows_compared': asm_compared,
    'functions': functions,
    'mapping': {'DOL_header_segment_count': len(header), 'BSS_start': hex(bss_start), 'BSS_size': bss_size, 'BSS_end_exclusive': hex(bss_start + bss_size), 'runtime_zeroing_claimed': False},
    'limitations': ['Only original main-DOL executable sections are scanned for explicit forms.', 'Indirect/aliased accesses and REL-module writes are outside this bounded search.', 'Matching SDA displacement has an absolute address only under startup r13=0x803B52C0.', 'Index domain is not native allocation size; unrelated named data exists within its addressable span.', 'No FP, paired-single, GPU or cache-counter semantic equivalence is claimed.'],
}
(OUT / 'word-audit.ai.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
(OUT / 'word-audit.md').write_text(f"# Cache original-word audit v2\n\nOriginal DOL SHA256 `{result['DOL_sha256']}`. Header mappings and segment hashes agree. Scanned {text_count} original text words: {result['counter_displacement_rows']} explicit counter SDA-displacement accesses, {result['table_low_half_candidates']} table low-half candidates, {len(branch_rows)} direct branches to interpreter. Retained {len(raw)} complete words in {len(entries)} bounded function/helper scopes; {asm_compared} retained ASM rows matched original words and file offsets. Raw CSV remains complete.\n\nThis proves explicit instruction forms only. Aliases, module writes, runtime initialization, allocation size and complete indirect callers remain unknown.\n", encoding='utf-8')
print(json.dumps({key: result[key] for key in ('text_words_scanned', 'counter_displacement_rows', 'table_low_half_candidates', 'direct_interpreter_branch_rows', 'aligned_literal_rows', 'bounded_original_words', 'retained_ASM_rows_compared')}, separators=(',', ':')))
