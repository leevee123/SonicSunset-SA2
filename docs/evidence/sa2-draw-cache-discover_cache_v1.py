from pathlib import Path
import csv
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
VIEWS = {
    'primary': ROOT / 'work/full-decompile/gekko/main/export',
    'startup_sda': ROOT / 'work/full-decompile/gekko/main-sda-v1/export',
}


def emit_csv(name, rows, fields):
    with (OUT / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


"""/* Scan the two frozen C views, keeping every named cache/counter reference.
This bounds negative findings to named symbols and cannot exclude bulk aliases. */"""
matches = []
hashes = []
counts = {}
symbol = re.compile(r'(?:DAT_|PTR_|UNK_|LAB_|FUN_)([0-9a-fA-F]{8})')
for view, folder in VIEWS.items():
    files = sorted((folder / 'pseudocode').glob('*.c'))
    counts[view] = len(files)
    for path in files:
        data = path.read_bytes()
        hashes.append({'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(data).hexdigest()})
        for number, line in enumerate(data.decode('utf-8').splitlines(), 1):
            addresses = [int(value, 16) for value in symbol.findall(line)]
            kinds = []
            if any(0x80357A58 <= address < 0x80357E58 for address in addresses):
                kinds.append('cache_table_named_range')
            if 0x803AE0F4 in addresses:
                kinds.append('cache_counter')
            if 0x8011CCF8 in addresses:
                kinds.append('interpreter_entry_or_call')
            if kinds:
                matches.append({'view': view, 'entry': path.stem, 'line': number, 'kind': '|'.join(kinds), 'text': line.strip(), 'path': str(path.relative_to(ROOT))})

"""/* Keep complete incoming call rows from both exported graphs. These graphs
do not prove complete indirect callers or original execution order. */"""
calls = []
for view, folder in VIEWS.items():
    path = folder / 'direct_calls.csv'
    data = path.read_bytes()
    hashes.append({'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(data).hexdigest()})
    with path.open(newline='', encoding='utf-8') as stream:
        for row in csv.DictReader(stream):
            if int(row['target'], 16) in {0x8011CCF8, 0x8011D414, 0x8011D2F4, 0x8011D410}:
                calls.append({'view': view, **row})

"""/* Verify original artifact identity and locate the cache within DOL BSS.
No file-backed byte offset is invented for uninitialized RAM. */"""
dol_path = ROOT / 'work/sa2-disc/main.dol'
dol = dol_path.read_bytes()
sha = hashlib.sha256(dol).hexdigest()
assert sha == 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'
mapping_path = ROOT / 'work/dol-elf-mapping-final.json'
mapping = json.loads(mapping_path.read_text())
hashes.extend({'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in (dol_path, mapping_path))
table_start = 0x80357A58
table_size = 256 * 4
bss = {'start': hex(mapping['bss_address']), 'end_exclusive': hex(mapping['bss_address'] + mapping['bss_size'])}
zero_ranges = [{'start': hex(a), 'end_exclusive': hex(b)} for a, b in mapping['zero_ranges'] if a <= table_start and table_start + table_size <= b]
assert zero_ranges

"""/* Reuse the initial bounded sample scan solely to inventory control stops;
its rows do not establish dynamic traversal or active cache definitions. */"""
sample_path = ROOT / 'work/sa2-payload-consumers/sample-stream4-commands.csv'
hashes.append({'path': str(sample_path.relative_to(ROOT)), 'sha256': hashlib.sha256(sample_path.read_bytes()).hexdigest()})
with sample_path.open(newline='', encoding='utf-8') as stream:
    controls = [row for row in csv.DictReader(stream) if int(row['opcode'], 16) in (4, 5)]
for row in controls:
    row['cache_index'] = str(int(row['header'], 16) >> 8)
    row['table_entry_va'] = hex(table_start + (int(row['header'], 16) >> 8) * 4)
    row['following_word_offset'] = hex(int(row['offset'], 16) + 2)

emit_csv('named-reference-lines.csv', matches, ['view', 'entry', 'line', 'kind', 'text', 'path'])
emit_csv('incoming-direct-calls.csv', calls, list(calls[0]))
emit_csv('initial-sample-cache-controls.csv', controls, list(controls[0]))
emit_csv('discovery-source-hashes.csv', hashes, ['path', 'sha256'])
result = {
    'version': 1,
    'scope': 'frozen main and startup-SDA generated C plus matching direct-call graphs; named-symbol search only',
    'counts': {'C_files': counts, 'matched_lines': len(matches), 'matched_functions': len({(r['view'], r['entry']) for r in matches}), 'incoming_graph_rows': len(calls), 'sample_control_stops': len(controls)},
    'matching_entries': sorted({row['entry'] for row in matches}),
    'table': {'base': hex(table_start), 'entry_stride': 4, 'index_bits': 8, 'max_index': 255, 'bytes': table_size, 'end_exclusive': hex(table_start + table_size), 'bss': bss, 'included_zero_range': zero_ranges, 'original_DOL_file_offset': None},
    'counter': {'va': '0x803ae0f4', 'startup_r13_displacement': hex((0x803AE0F4 - 0x803B52C0) & 0xffff)},
    'DOL_sha256': sha,
    'limitations': ['Named-symbol matches do not exclude alias/bulk initialization or indirect calls.', 'Two C views are alternative analyses of the same original bytes.', 'Sample rows stop at command4/5; file order is not an execution-order proof.'],
}
(OUT / 'discovery.ai.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
(OUT / 'discovery.md').write_text(f"# Draw-cache discovery v1\n\nScanned {sum(counts.values())} frozen generated C files ({counts}); {len(matches)} named reference lines in {result['counts']['matched_functions']} view/function pairs. Complete lines, call rows and source hashes are retained. Table 0x80357A58 has 256 four-byte slots through exclusive {hex(table_start + table_size)}; it lies in original DOL BSS and has no file-backed bytes.\n\nThis search only bounds named-symbol references. Bulk aliases, indirect calls, runtime order, and cache initialization remain unproved. Sample cache/control stops are inventory only.\n", encoding='utf-8')
print(json.dumps({'counts': result['counts'], 'entries': result['matching_entries'], 'table': result['table']}, separators=(',', ':')))
