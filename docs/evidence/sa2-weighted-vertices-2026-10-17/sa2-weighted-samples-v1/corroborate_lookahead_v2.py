import csv
import hashlib
import json
import struct
from collections import Counter
from pathlib import Path

out = Path(__file__).resolve().parent
base = out.parents[1]
native = base / 'work/sa2-weighted-transform-v1'
sha = lambda data: hashlib.sha256(data).hexdigest()
number = lambda value: int(value, 0)
rows = lambda path: list(csv.DictReader(path.open(newline='', encoding='utf-8-sig')))
assert not (out / 'lookahead-corroboration.ai.json').exists(), 'Do not rerun a completed version.'
paths = [out / 'summary.ai.json', out / 'weighted-packets.csv', out / 'post-declared-packet-windows.csv', out / 'corroborate_lookahead_v1.py', native / 'raw-audit.md', native / 'raw-audit.ai.md', native / 'raw-audit.ai.json', native / 'original-words.csv', native / 'PSQ-fields.csv', Path(__file__)]
before = {path.resolve(): sha(path.read_bytes()) for path in paths}
report = json.loads((out / 'summary.ai.json').read_text())
expected = {r['name']: r['sha256'] for r in report['artifacts']}
for name in ('weighted-packets.csv', 'post-declared-packet-windows.csv'):
    assert sha((out / name).read_bytes()) == expected[name]
dol = (base / 'work/sa2-disc/main.dol').read_bytes()
assert sha(dol) == 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e'
decoded = (base / 'work/sa2-bank-layout-v1/decoded-bank.bin').read_bytes()
assert sha(decoded) == report['decoded_sha256']
mapping = json.loads((base / 'work/dol-elf-mapping-final.json').read_text())
def offset(address):
    values = [r['dol_offset'] + address - r['address'] for r in mapping['mappings'] if r['address'] <= address < r['address'] + r['size']]
    assert len(values) == 1
    return values[0]
word_rows = rows(native / 'original-words.csv')
fields = list(word_rows[0])
va_key = next(k for k in fields if k.lower() in ('va', 'original_virtual_address', 'address'))
word_key = next(k for k in fields if k.lower() == 'word')
words = {}
for row in word_rows:
    address, word = number(row[va_key]), int(row[word_key], 16)
    assert struct.unpack_from('>I', dol, offset(address))[0] == word
    words[address] = word
required_sites = [0x8011dcf0, 0x8011dcf8, 0x8011dd10, 0x8011dd1c, 0x8011dd20, 0x8011dd3c, 0x8011dd84, 0x8011dd88, 0x8011de24, 0x8011de30, 0x8011de40, 0x8011de44, 0x8011de48, 0x8011de7c, 0x8011deb4, 0x8011dec0, 0x8011dec4, 0x8011dec8]
assert all(address in words for address in required_sites)
assert words[0x8011dd1c] == words[0x8011de44] == words[0x8011dec4] == 0xe6679008
packets = rows(out / 'weighted-packets.csv')
windows = {row['packet_offset']: row for row in rows(out / 'post-declared-packet-windows.csv')}
coverage = []
for packet in packets:
    mode, count = int(packet['masked_variant_7bits']), int(packet['count'])
    assert mode in (0, 1, 2) and count > 0
    required = 24 if mode != 0 and count == 1 else 28
    window = windows[packet['packet_offset']]
    start = number(window['post_declared_window_offset'])
    assert int(window['post_declared_available_bytes_up_to28']) >= required
    raw = decoded[start:start + required]
    assert window['post_declared_raw_bytes'].startswith(raw.hex())
    coverage.append({'packet_offset': packet['packet_offset'], 'mode_raw_variant': mode, 'count': count, 'post_declared_offset': hex(start), 'Float32_contract_lookahead_bytes': required, 'covered_by_preserved_window': True, 'original_bytes': raw.hex(), 'sha256': sha(raw), 'following_same_stream_opcode': window['following_same_stream_opcode'], 'claim_scope': 'source-derived access range under explicit GQR0 float layout; unused terminal preloads are not declared records'})
with (out / 'lookahead-window-coverage.csv').open('w', newline='', encoding='utf-8') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(coverage[0]))
    writer.writeheader()
    writer.writerows(coverage)
with (out / 'lookahead-original-sites.csv').open('w', newline='', encoding='utf-8') as stream:
    writer = csv.DictWriter(stream, fieldnames=['VA', 'DOL_offset', 'ISO_offset', 'word'])
    writer.writeheader()
    writer.writerows({'VA': hex(address), 'DOL_offset': hex(offset(address)), 'ISO_offset': hex(0x1e700 + offset(address)), 'word': hex(words[address])} for address in required_sites)
for path, digest in before.items():
    assert sha(path.read_bytes()) == digest
stats = {'version': 2, 'result': 'passed', 'native_original_word_rows_rechecked': len(word_rows), 'selected_control_load_sites': len(required_sites), 'real_weighted_packets_covered': len(coverage), 'lookahead_byte_count_histogram_under_Float32_contract': dict(Counter(r['Float32_contract_lookahead_bytes'] for r in coverage)), 'all_windows_cover_source_derived_access_range': True, 'declared_packet_tails_added': False, 'runtime_register_state_or_execution_observed': False, 'script_runs': 'corroborate_lookahead_v2.py once', 'prior_version_failure': 'V1 int(value,0) rejected bare hexadecimal instruction word; V2 uses explicit base16. No byte or native-code change.'}
details = {'summary': stats, 'source_report': str(native / 'raw-audit.md'), 'instruction_source': str(native / 'original-words.csv'), 'source_snapshots': [{'path': str(path), 'sha256': digest} for path, digest in before.items()], 'scope': 'Native control-flow facts are cross-referenced to the independent original-word audit; this script rechecks words and original-byte range coverage, not numerical results or CPU execution.'}
(out / 'lookahead-corroboration.ai.json').write_text(json.dumps(details, indent=2) + '\n', encoding='utf-8')
(out / 'lookahead-corroboration.md').write_text('# Weighted lookahead file corroboration v2\n\nOne V2 run passed. V1 stopped before byte coverage because it parsed bare hexadecimal words with int(value,0); its script and paired failure record are retained. This adds original-instruction evidence to the earlier file-only windows; it does not change the frozen first report or classify following bytes as padding.\n\nMachine result: ' + json.dumps(stats, separators=(',', ':')) + '\n\nThe independent original-word audit in ../sa2-weighted-transform-v1/raw-audit.md verifies entry loads at DCF0/DCF8/DD10, fixed GQR1 weight loadDD1C and destinationLHZDD20, then next input pairDD3C. Mode0 preloads the complete next record before count-1 testing at DD84/DD88. For a nonzero mode with count1, DE40 branches before DE44/DE48 weight/destination loads, leaving only the six scalar slots (24bytes in the explicit Float32 layout) beyond the declared packet. For nonzero count>=2, the loop preloads the full28-byte next record via DE7C/DEB4/DEC0/DEC4/DEC8. All source words were rechecked against the fixed original DOL.\n\nEvery real positive-count weighted packet\'s preserved post-declared window covers the corresponding access range. The consumed packet remains count*28 bytes; these are pipeline reads into following file bytes and do not establish an extra declared record. Exact numeric results, unused-lane behavior, live GQR0/FPSCR, aliasing, CPU faults and actual execution remain the separate numerical/native audit\'s scope. Complete raw ranges and byte hashes are in lookahead-window-coverage.csv; VA/DOL/ISO words are in lookahead-original-sites.csv.\n', encoding='utf-8')
print(json.dumps(stats, separators=(',', ':')))
