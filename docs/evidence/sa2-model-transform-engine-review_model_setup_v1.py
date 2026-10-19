from pathlib import Path
import csv
import hashlib
import json
import struct

work = Path(__file__).resolve().parent
out = work / 'sa2-model-setup-v1'
rows = list(csv.DictReader((out / 'original-words.csv').open(newline='')))
entries = {0x8011D2F4, 0x80105850, 0x8010588C, 0x80105908, 0x800ED798, 0x800ED7CC}
sections = json.loads((work / 'dol-elf-mapping-final.json').read_text())['mappings']
dol = (work / 'sa2-disc/main.dol').read_bytes()
def offset(va):
    return next(s['dol_offset'] + va - s['address'] for s in sections if s['address'] <= va < s['address'] + s['size'])
constants = []
for va in (0x803B0FB8, 0x803B0FBC, 0x803B0FC0, 0x803B0FC4, 0x803B07C8, 0x803B07CC):
    off = offset(va)
    constants.append({'VA': hex(va), 'DOL_offset': hex(off), 'ISO_offset': hex(off + 0x1E700), 'word': dol[off:off+4].hex(), 'f32': struct.unpack_from('>f', dol, off)[0]})
with (out / 'bootstrap-constants.csv').open('w', newline='') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(constants[0]))
    writer.writeheader(); writer.writerows(constants)
text = '# Model setup: bounded original-word review\n\n' + '\n'.join(f"{r['VA']} DOL {r['DOL_offset']} ISO {r['ISO_offset']}: {r['word']} = {r['f32']}" for r in constants) + '\n'
for entry in sorted(entries):
    selected = [r for r in rows if int(r['owner'], 16) == entry]
    text += f'\n## {entry:08X} ({len(selected)} words)\n\n' + '\n'.join(r['original_virtual_address'] + ' ' + r['instruction'] for r in selected) + '\n'
(out / 'word-review.md').write_text(text)
report = {'constants': constants, 'selected_words': sum(int(r['owner'], 16) in entries for r in rows), 'DOL_sha256': hashlib.sha256(dol).hexdigest(), 'review_md_sha256': hashlib.sha256(text.encode()).hexdigest(), 'limits': 'GQR0/FPSCR live state unknown; original words only, no runtime execution. selected-pseudocode.md labels complete but truncates >100-line selection; original full C hashes retained, not relied on for exact PS math.'}
(out / 'word-review.ai.json').write_text(json.dumps(report, indent=2) + '\n')
print(text)
