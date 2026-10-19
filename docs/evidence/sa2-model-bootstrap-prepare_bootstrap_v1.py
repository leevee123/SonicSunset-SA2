import csv
import hashlib
import json
import os
import re
import struct
import subprocess
from pathlib import Path

out = Path(__file__).resolve().parent
base = out.parents[1]
prior = base / 'work/sa2-model-setup-v1'
sha = lambda data: hashlib.sha256(data).hexdigest()
rows = lambda path: list(csv.DictReader(path.open(newline='', encoding='utf-8-sig')))
protected = {}
assert not (out / 'preparation.ai.json').exists(), 'Do not rerun a completed version.'
def protect(path, role, expected=None):
    path = path.resolve()
    data = path.read_bytes()
    digest = sha(data)
    assert expected is None or digest == expected, str(path)
    item = protected.setdefault(path, {'path': str(path), 'roles': set(), 'sha256_before': digest, 'bytes_before': len(data), 'expected_sha256': expected or ''})
    assert item['sha256_before'] == digest
    item['roles'].add(role)
    if expected:
        assert not item['expected_sha256'] or item['expected_sha256'] == expected
        item['expected_sha256'] = expected
    return data
def write(name, values, fields=None):
    if fields is None:
        fields = list(dict.fromkeys(key for row in values for key in row))
    with (out / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(values)
for name in ('source-artifacts.csv', 'original-words.csv', 'bootstrap-constants.csv', 'preparation.ai.json', 'word-review.ai.json', 'word-review.md', 'java-arguments.txt'):
    protect(prior / name, 'root_prepared_evidence')
for row in rows(prior / 'source-artifacts.csv'):
    protect(Path(row['path']), 'root_recorded_original_' + row['kind'], row['sha256'])
dol_path = base / 'work/sa2-disc/main.dol'
dol = protect(dol_path, 'original_DOL', 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e')
mapping_path = base / 'work/dol-elf-mapping-final.json'
protect(mapping_path, 'canonical_DOL_mapping')
mapping = json.loads(mapping_path.read_text())
def offset(address):
    matches = [m['dol_offset'] + address - m['address'] for m in mapping['mappings'] if m['address'] <= address < m['address'] + m['size']]
    assert len(matches) == 1
    return matches[0]
for row in rows(prior / 'original-words.csv'):
    address, file_offset = int(row['original_virtual_address'], 16), int(row['dol_file_offset'], 16)
    assert offset(address) == file_offset
    assert struct.unpack_from('>I', dol, file_offset)[0] == int(row['word'], 16)
entries = {0x801057c4, 0x801057f8, 0x8010582c, 0x8011c18c}
sources, ranges, structures = [], [], []
for view, folder in [('main', base / 'work/full-decompile/gekko/main/export'), ('sda', base / 'work/full-decompile/gekko/main-sda-v1/export')]:
    protect(folder / 'functions.csv', 'frozen_function_catalog')
    catalog = {int(r['entry'], 16): r for r in rows(folder / 'functions.csv')}
    for entry in sorted(entries):
        record = catalog[entry]
        addresses = [int(value, 16) for value in re.findall(r'[0-9a-fA-F]{8}', record['body_ranges'])]
        assert len(addresses) > 0 and len(addresses) % 2 == 0
        if view == 'main':
            for index in range(0, len(addresses), 2):
                ranges.append({'owner': hex(entry), 'start': hex(addresses[index]), 'end_exclusive': hex(addresses[index + 1] + 1)})
        for kind in ('pseudocode', 'assembly'):
            if not record[kind + '_path']:
                continue
            path = folder / record[kind + '_path']
            data = protect(path, 'new_recorded_original_' + kind, record[kind + '_sha256'])
            sources.append({'view': view, 'entry': hex(entry), 'DOL_offset': hex(offset(entry)), 'ISO_offset': hex(0x1e700 + offset(entry)), 'kind': kind, 'path': str(path), 'sha256': sha(data), 'body_ranges': record['body_ranges'], 'status': record['status']})
            if view == 'sda' and kind == 'pseudocode':
                lines = data.decode('utf-8').splitlines()
                for line_no, line in enumerate(lines, 1):
                    if re.search(r'DAT_|pfVar\d+ = |pfVar\d+\[|FUN_|return;', line):
                        structures.append({'entry': hex(entry), 'line': line_no, 'text': line.strip(), 'source_path': str(path), 'selection': 'structural excerpts only; full source hash retained', 'full_source_lines': len(lines)})
write('added-source-artifacts.csv', sources)
write('C-structural-excerpts.csv', structures)
with (out / 'function-ranges.tsv').open('w', newline='', encoding='utf-8') as stream:
    writer = csv.DictWriter(stream, fieldnames=['owner', 'start', 'end_exclusive'], delimiter='\t')
    writer.writeheader()
    writer.writerows(ranges)
helper = base / 'work/sonicmdl-loader/DumpSonicLoader.java'
protect(helper, 'existing_project_free_parser_source')
protect(base / 'work/sonicmdl-loader/classes/DumpSonicLoader.class', 'existing_compiled_project_free_parser')
language = base / 'work/full-decompile-fp/Sa2GekkoLanguage/data/languages'
for name in ('ppc_gekko_broadway.slaspec', 'ppc_gekko_broadway.sla'):
    protect(language / name, 'frozen_processor_language')
protect(Path(__file__), 'preparation_script')
arguments = [json.loads(line) for line in (prior / 'java-arguments.txt').read_text().splitlines() if line.strip()]
for index, argument in enumerate(arguments):
    if argument.startswith(('-Duser.home=', '-Dapplication.settingsdir=', '-Dapplication.cachedir=', '-Djava.io.tmpdir=')):
        arguments[index] = argument.replace(str(prior.resolve()), str(out.resolve()))
arguments[-2:] = [str((out / 'function-ranges.tsv').resolve()), str((out / 'added-original-words.csv').resolve())]
(out / 'java-arguments.txt').write_text('\n'.join(json.dumps(value) for value in arguments) + '\n', encoding='utf-8')
for name in ('home', 'settings', 'cache', 'tmp'):
    (out / 'runtime' / name).mkdir(parents=True, exist_ok=True)
env = os.environ.copy()
env.update(TEMP=str((out / 'runtime/tmp').resolve()), TMP=str((out / 'runtime/tmp').resolve()))
java = Path('C:/decomp/sonic-adventure-gc/jdk-21.0.12.1+1/bin/java.exe')
with (out / 'parser.raw.log').open('w', encoding='utf-8') as log:
    result = subprocess.run([str(java), '@' + str((out / 'java-arguments.txt').resolve())], cwd=base, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=90)
assert result.returncode == 0
new_words = rows(out / 'added-original-words.csv')
for row in new_words:
    address, file_offset = int(row['original_virtual_address'], 16), int(row['dol_file_offset'], 16)
    assert offset(address) == file_offset
    assert struct.unpack_from('>I', dol, file_offset)[0] == int(row['word'], 16)
assert len(new_words) == sum((int(r['end_exclusive'], 16) - int(r['start'], 16)) // 4 for r in ranges)
digests = []
for path, item in sorted(protected.items(), key=lambda pair: str(pair[0])):
    data = path.read_bytes()
    assert sha(data) == item['sha256_before'] and len(data) == item['bytes_before'], str(path)
    digests.append(dict(item, roles='|'.join(sorted(item['roles'])), sha256_after=sha(data), bytes_after=len(data), unchanged=True))
write('preparation-source-digests.csv', digests)
stats = {'result': 'passed', 'added_functions': len(entries), 'added_source_artifacts': len(sources), 'added_ranges': len(ranges), 'added_original_words': len(new_words), 'prior_original_words_verified': len(rows(prior / 'original-words.csv')), 'protected_sources_unchanged': len(digests), 'native_game_execution': False, 'project_or_ProgramDB_opens': 0, 'parser_exit': result.returncode, 'parser_log_sha256': sha((out / 'parser.raw.log').read_bytes()), 'script_runs': 'prepare_bootstrap_v1.py once'}
(out / 'preparation.ai.json').write_text(json.dumps(stats, indent=2) + '\n', encoding='utf-8')
(out / 'preparation.md').write_text('# Bootstrap scope preparation v1\n\nOne run passed. Full frozen C hashes were checked first; structural excerpts are explicitly partial. Existing DumpSonicLoader parsed original DOL words using frozen isolated language definitions and private runtime paths. No Program or project was opened.\n\n' + json.dumps(stats, separators=(',', ':')) + '\n', encoding='utf-8')
print(json.dumps(stats, separators=(',', ':')))
