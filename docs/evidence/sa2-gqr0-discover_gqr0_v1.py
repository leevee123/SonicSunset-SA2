"""One bounded original main-DOL GQR SPR access scan; no database or runtime."""
import csv
import hashlib
import json
import re
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[1]
assert not (OUT / 'discovery.ai.json').exists()
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
    if not fields:
        fields = ['scope', 'result']
    with (OUT / name).open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fields)
        w.writeheader()
        w.writerows(values)


dol = read(ROOT / 'work/sa2-disc/main.dol')
mapping = json.loads(read(ROOT / 'work/dol-elf-mapping-final.json'))
assert hashlib.sha256(dol).hexdigest() == mapping['dol_sha256'] == 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'
with (ROOT / 'work/sa2.iso').open('rb') as f:
    f.seek(0x420)
    iso_base = struct.unpack('>I', f.read(4))[0]
    f.seek(iso_base)
    assert f.read(len(dol)) == dol
language = ROOT / 'work/full-decompile-fp/Sa2GekkoLanguage/data/languages'
spec = read(language / 'ppc_gekko_broadway.slaspec').decode('utf-8-sig')
embedded = read(language / 'ppc_embedded.sinc').decode('utf-8-sig')
gekko_path = ROOT / 'work/full-decompile-fp/Gekko.pinned.h'
gekko = read(gekko_path).decode()
assert ':mfspr D,SPRVAL' in embedded and 'XOP_1_10=339 & BIT_0=0' in embedded
assert ':mtspr SPRVAL,S' in embedded and 'XOP_1_10=467 & BIT_0=0' in embedded
assert 'SPR_GQR0 = 912' in gekko
table = spec.split('attach variables SPRVAL [', 1)[1].split(']', 1)[0].split()
assert len(table) == 1024
selector_cases = []
for spr in range(1024):
    raw = ((spr & 31) << 5) | (spr >> 5)
    decoded = (raw >> 5) | ((raw & 31) << 5)
    assert decoded == spr
    if 912 <= spr <= 919:
        assert table[raw] == 'GQR' + str(spr - 912)
    selector_cases.append({'SPR_decimal': spr, 'raw_instruction_field': hex(raw), 'decoded_SPR': decoded, 'SLEIGH_register_label': table[raw]})
definition_rows = []
for path, text, patterns in [(language / 'ppc_embedded.sinc', embedded, [':mfspr D,SPRVAL', ':mtspr SPRVAL,S']), (language / 'ppc_gekko_broadway.slaspec', spec, ['SPRVAL=(11,20)', 'GQR0   \tspr3b0']), (gekko_path, gekko, ['SPR_GQR0 = 912'])]:
    for line, content in enumerate(text.splitlines(), 1):
        if any(p in content for p in patterns):
            definition_rows.append({'path': str(path), 'line': line, 'text': content})

segments, hits, rejected, text_words = [], [], [], 0
for i in range(7):
    position, address, size = (struct.unpack_from('>I', dol, start + 4 * i)[0] for start in [0, 0x48, 0x90])
    if not size:
        continue
    m = next(m for m in mapping['mappings'] if m['address'] == address)
    assert position == m['dol_offset'] and size == m['size'] and hashlib.sha256(dol[position:position + size]).hexdigest() == m['sha256']
    segments.append({'text_section': i, 'va': hex(address), 'end_exclusive': hex(address + size), 'dol_offset': hex(position), 'iso_offset': hex(iso_base + position), 'bytes': size, 'sha256': m['sha256']})
    for p in range(position, position + size, 4):
        text_words += 1
        w = struct.unpack_from('>I', dol, p)[0]
        if w >> 26 != 31 or (w >> 1) & 1023 not in [339, 467]:
            continue
        spr = ((w >> 16) & 31) | (((w >> 11) & 31) << 5)
        if not 912 <= spr <= 919:
            continue
        row = {'va': hex(address + p - position), 'dol_offset': hex(p), 'iso_offset': hex(iso_base + p), 'word': hex(w), 'SPR': spr, 'GQR': spr - 912, 'access': 'read_mfspr' if (w >> 1) & 1023 == 339 else 'write_mtspr', 'gpr': (w >> 21) & 31, 'BIT_0': w & 1, 'classification': 'exact valid instruction encoding candidate; static word presence not execution'}
        (rejected if w & 1 else hits).append(row)

owners, sources = [], []
for view in ['main', 'main-sda-v1']:
    base = ROOT / 'work/full-decompile/gekko' / view / 'export'
    catalog = {int(r['entry'], 16): r for r in rows(base / 'functions.csv')}
    ranges = rows(base / 'function_body_ranges.csv')
    selected = set()
    for hit in hits:
        va = int(hit['va'], 16)
        matching = [r for r in ranges if int(r['range_start'], 16) <= va < int(r['range_end_exclusive'], 16)]
        for r in matching:
            entry = int(r['entry'], 16)
            owners.append({'view': view, **hit, 'entry': hex(entry), 'range_start': r['range_start'], 'range_end_exclusive': r['range_end_exclusive'], 'status': catalog[entry]['status']})
            selected.add(entry)
        if not matching:
            owners.append({'view': view, **hit, 'entry': '', 'status': 'not owned by exported body ranges'})
    for entry in sorted(selected):
        row = catalog[entry]
        for kind in ['pseudocode', 'assembly']:
            if not row[kind + '_path']:
                continue
            path = base / row[kind + '_path']
            data = read(path)
            assert hashlib.sha256(data).hexdigest() == row[kind + '_sha256']
            sources.append({'view': view, 'entry': hex(entry), 'kind': kind, 'path': str(path), 'sha256': row[kind + '_sha256'], 'status': row['status'], 'body_ranges': row['body_ranges']})
save('original-text-segments.csv', segments)
save('all-GQR-accesses.csv', hits)
save('reserved-bit-rejected-candidates.csv', rejected)
save('GQR-access-owners.csv', owners)
save('owner-source-artifacts.csv', sources)
save('instruction-definition-lines.csv', definition_rows)
save('SPR-selector-domain.csv', selector_cases)
save('discovery-input-sha256.csv', [{'path': p, 'sha256': d} for p, d in sorted(inputs.items())])
gqr0 = [r for r in hits if r['GQR'] == 0]
result = {'result': 'passed', 'DOL_sha256': hashlib.sha256(dol).hexdigest(), 'DOL_ISO_base': hex(iso_base), 'text_sections': len(segments), 'text_words_scanned': text_words, 'all_GQR_accesses': len(hits), 'GQR0_accesses': len(gqr0), 'GQR0_writes': sum(r['access'] == 'write_mtspr' for r in gqr0), 'GQR0_reads': sum(r['access'] == 'read_mfspr' for r in gqr0), 'reserved_bit_rejected_candidates': len(rejected), 'GQR0_sites': gqr0, 'GQR0_owner_entries': sorted({r['entry'] for r in owners if r['GQR'] == 0 and r['entry']}), 'source_artifacts': len(sources), 'SPR_selector_cases': len(selector_cases), 'scope': 'Main DOL original text words only; no REL/apploader/copied/new/runtime code or implicit hardware paths.', 'native_execution': False, 'project_opens': 0}
(OUT / 'discovery.ai.json').write_text(json.dumps(result, indent=2) + '\n')
(OUT / 'discovery.md').write_text('# Main-DOL GQR discovery\n\nOne bounded scan matched original DOL text sections and real ISO bytes. Instruction selectors were checked against the local immutable Gekko SLEIGH definitions and pinned primary SPR constant. Exact GQR0 and contextual GQR1..7 encodings, source ownership, source digests and all1024 selector cases remain complete in CSV. Static presence is not execution; other carriers/hardware/runtime paths are outside scope.\n')
print(json.dumps(result, separators=(',', ':')))
for r in sources:
    if any(o['GQR'] == 0 and o['entry'] == r['entry'] for o in owners) and r['kind'] == 'pseudocode':
        print(json.dumps({'view': r['view'], 'entry': r['entry'], 'C': Path(r['path']).read_text()}, separators=(',', ':')))
