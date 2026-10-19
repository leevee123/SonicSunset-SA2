import csv
import hashlib
import json
from pathlib import Path

folder = Path(__file__).resolve().parent


def polish(value):
    if isinstance(value, dict):
        return {key: polish(item) for key, item in value.items()}
    if isinstance(value, list):
        return [polish(item) for item in value]
    if isinstance(value, str):
        for before, after in {
            'state bit2': 'state mask0x2',
            ' bit2 ': ' mask0x2 ',
            'state0x803AE148': 'state0x803AE148',
            'opcode40': 'opcode0x40',
            'opcode41/42': 'opcode0x41/0x42',
            'opcode42': 'opcode0x42',
            'preserves incoming r3..r6': 'forwards incoming r3..r6',
        }.items():
            value = value.replace(before, after)
    return value


"""/* Clarify that the state selector is numeric mask0x2, not bit index2.
Only final prose/contracts change; raw evidence and source guards stay untouched. */"""
ai_path = folder / 'dispatch-contract.ai.json'
ai_path.write_text(json.dumps(polish(json.loads(ai_path.read_text(encoding='utf-8'))), indent=2) + '\n', encoding='utf-8')
human_path = folder / 'dispatch-contract.md'
text = polish(human_path.read_text(encoding='utf-8'))
for before, after in {
    'opcode 40': 'opcode 0x40',
    'opcode 41/42': 'opcodes 0x41/0x42',
    'opcode41': 'opcode0x41',
    'opcode 41': 'opcode 0x41',
    'opcode 42': 'opcode 0x42',
    'state mask0x2': 'state mask 0x2',
    'scratch+0,+4,+8, then+C,+10,+14': 'scratch+0x00,+0x04,+0x08, then+0x0C,+0x10,+0x14',
    'scratch+18': 'scratch+0x18',
    'enables13+i': 'enables 13+i',
    'and20158': 'and 20158',
}.items():
    text = text.replace(before, after)
human_path.write_text(text, encoding='utf-8')
csv_path = folder / 'handler-layout-contract.csv'
with csv_path.open(newline='', encoding='utf-8') as stream:
    layouts = list(csv.DictReader(stream))
with csv_path.open('w', newline='', encoding='utf-8') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(layouts[0]))
    writer.writeheader()
    writer.writerows(polish(layouts))

manifest = json.loads((folder / 'manifest.ai.json').read_text(encoding='utf-8'))
files = [{'path': path.name, 'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(folder.iterdir()) if path.is_file() and not path.name.startswith('manifest.')]
manifest['files'] = files
with (folder / 'manifest.csv').open('w', newline='', encoding='utf-8') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(files[0]))
    writer.writeheader()
    writer.writerows(files)
(folder / 'manifest.ai.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
(folder / 'manifest.md').write_text(f"# Geometry dispatch manifest\n\n{len(files)} complete artifacts with SHA256 and size in CSV/AI twin. Handoff: dispatch-contract.md/.ai.json; full original words, FIFO sites, handler contracts and 129 unchanged source guards. No repository/engine/original/frozen/project changes.\n", encoding='utf-8')
print(json.dumps({'ready': True, 'notation': 'state selector is mask0x2; opcodes are hexadecimal', 'source_guards': 129, 'files': len(files)}))
