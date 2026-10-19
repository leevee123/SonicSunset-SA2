import csv
import hashlib
import json
import re
import struct
from collections import Counter, defaultdict, deque
from pathlib import Path

out = Path(__file__).resolve().parent
base = out.parents[1]
prior = base / 'work/sa2-payload-consumers'
sha = lambda data: hashlib.sha256(data).hexdigest()
number = lambda value: int(value, 0)
rows = lambda path: list(csv.DictReader(path.open(newline='', encoding='utf-8-sig')))
protected = {}

def protect(path, role, expected=None, length=None):
    path = path.resolve()
    data = path.read_bytes()
    digest = sha(data)
    assert expected is None or digest == expected, str(path)
    assert length is None or len(data) == length, str(path)
    record = protected.setdefault(path, {'path': str(path), 'roles': set(), 'bytes_before': len(data), 'sha256_before': digest, 'expected_sha256': expected or ''})
    assert record['sha256_before'] == digest
    record['roles'].add(role)
    if expected:
        assert not record['expected_sha256'] or record['expected_sha256'] == expected
        record['expected_sha256'] = expected
    return data

def write(name, values, fields=None):
    if fields is None:
        fields = list(dict.fromkeys(key for row in values for key in row))
    with (out / name).open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(values)

assert not (out / 'summary.ai.json').exists(), 'Do not rerun a completed version.'
for name in ('input-artifacts.csv', 'consumer-source-artifacts.csv', 'consumer-original-words.csv', 'sample-stream4-commands.csv', 'sample-payload-headers.csv', 'discover_consumers_v1.py'):
    protect(prior / name, 'prior_consumer_evidence')
for row in rows(prior / 'input-artifacts.csv'):
    protect(Path(row['path']), 'recorded_input', row['sha256'], int(row['bytes']))
sources = rows(prior / 'consumer-source-artifacts.csv')
for row in sources:
    protect(Path(row['path']), 'recorded_original_code_' + row['kind'], row['sha256'])
protect(Path(__file__), 'inventory_script')
decoded = protect(base / 'work/sa2-disc/sonicmdl.prs.decoded', 'decoded_bank', 'b7ea586ed0fa22330dc8a2cfe2bb8fa9ce4ac70d9561764f35af4ced5d371963', 136360)
dol = protect(base / 'work/sa2-disc/main.dol', 'original_DOL', 'a53335308d1f820be236fd2b6342fee850eaf048eb26aac21ddb1903b060db2e', 1960448)
mapping_path = base / 'work/dol-elf-mapping-final.json'
protect(mapping_path, 'DOL_mapping')
mapping = json.loads(mapping_path.read_text())
def dol_offset(address):
    matches = [m['dol_offset'] + address - m['address'] for m in mapping['mappings'] if m['address'] <= address < m['address'] + m['size']]
    assert len(matches) == 1
    return matches[0]

native = rows(prior / 'consumer-original-words.csv')
for row in native:
    address = number(row['original_virtual_address'])
    offset = number(row['dol_offset'])
    assert offset == dol_offset(address)
    assert struct.unpack_from('>I', dol, offset)[0] == number(row['word'])
selected_words = [r for r in native if r['view'] == 'sda' and r['entry'] == '0x8011ccf8']
assert selected_words
original = {number(r['original_virtual_address']): number(r['word']) for r in selected_words}
for address, word in {0x8011cda8: 0x92830000, 0x8011cdb8: 0x480003dc, 0x8011cdcc: 0x80630000, 0x8011cdd4: 0x4bffff25, 0x8011ce28: 0xab340000, 0x8011ce68: 0xa3630000, 0x8011ce6c: 0xa8140000, 0x8011cf2c: 0x574093be, 0x8011d168: 0x381bffff, 0x8011d16c: 0x5400083c, 0x8011d170: 0x7e940214, 0x8011d184: 0xab940000, 0x8011d18c: 0x2c1c00ff}.items():
    assert original[address] == word, hex(address)
u16 = lambda offset: struct.unpack_from('>H', decoded, offset)[0]
s16 = lambda value: value if value < 0x8000 else value - 0x10000
u32 = lambda offset: struct.unpack_from('>I', decoded, offset)[0]

def rotate32(value, amount):
    return ((value << amount) | (value >> (32 - amount))) & 0xffffffff

def group_expression(word):
    signed = s16(word)
    original_masked_rotate = rotate32(signed & 0xffffffff, 18) & 0x3ffff
    assert original_masked_rotate == ((signed & 0xffffffff) >> 14)
    return original_masked_rotate

expression_differences = sum(group_expression(word) != word >> 14 for word in range(0x10000))
headers = rows(prior / 'sample-payload-headers.csv')
roots = defaultdict(list)
for row in headers:
    payload = number(row['payload_offset'])
    assert decoded[payload:payload + 24].hex() == row['raw_24_bytes']
    assert u32(payload) == number(row['stream_0']) and u32(payload + 4) == number(row['stream_4'])
    if u32(payload + 4):
        roots[u32(payload + 4)].append(payload)

commands = {}
def command(offset):
    if offset in commands:
        return commands[offset]
    assert 0 <= offset and offset + 2 <= len(decoded) and offset % 2 == 0
    header = u16(offset)
    opcode = header & 0xff
    record = {'offset': hex(offset), 'header': hex(header), 'header_high8': header >> 8, 'header_signed16': s16(header), 'opcode': hex(opcode)}
    if header == 0xff:
        end, kind = offset + 2, 'exact_00ff_return'
    elif opcode == 4:
        end, kind = offset + 2, 'cache_define_following_pointer_and_return'
        record.update(cache_slot=header >> 8, cache_body_offset=hex(end))
    elif opcode == 5:
        end, kind = offset + 2, 'cache_call_then_local_continuation_if_call_returns'
        record.update(cache_slot=header >> 8, local_continuation_offset=hex(end))
    elif opcode < 8:
        end, kind = offset + 2, 'single_halfword_control'
    elif opcode < 0x10:
        end, kind = offset + 4, 'header_and_signed_argument'
        record.update(argument_halfword=hex(u16(offset + 2)), argument_signed16=s16(u16(offset + 2)))
    elif opcode < 0x40:
        size_word = u16(offset + 2)
        signed_size = s16(size_word)
        assert signed_size >= 0, 'Sample negative size must be retained as unsupported, not coerced.'
        end, kind = offset + 4 + 2 * signed_size, 'signed_size_prefixed_state_operation'
        record.update(size_halfwords=signed_size, size_word=hex(size_word), data_offset=hex(offset + 4), data_bytes=2 * signed_size)
    else:
        size_word = u16(offset + 2)
        count = u16(offset + 4)
        end, kind = offset + 4 + 2 * size_word, 'geometry_40_42' if opcode <= 0x42 else 'other_ge40_raw_skip'
        assert size_word >= 1, 'Sample geometry skip underflow requires a separate audit.'
        record.update(size_halfwords=size_word, size_word=hex(size_word), count_word=hex(count), count_signed16=s16(count), count_low14=count & 0x3fff, count_high2=count >> 14, original_sign_extended_group_expression=group_expression(count), data_offset=hex(offset + 6), data_bytes=end - offset - 6)
    assert offset < end <= len(decoded), hex(offset)
    record.update(classification=kind, next_offset=hex(end), byte_size=end - offset, raw_bytes=decoded[offset:end].hex(), raw_sha256=sha(decoded[offset:end]))
    commands[offset] = record
    return record

queue = deque(roots)
entry_roles = defaultdict(set)
entry_parents = defaultdict(set)
for start in roots:
    entry_roles[start].add('payload_stream4')
entries = {}
occurrences = []
while queue:
    start = queue.popleft()
    if start in entries:
        continue
    offset = start
    local = []
    for order in range(10000):
        record = command(offset)
        local.append(offset)
        occurrences.append({'entry_offset': hex(start), 'local_order': order, 'command_offset': hex(offset), 'opcode': record['opcode'], 'classification': record['classification'], 'cache_slot': record.get('cache_slot', '')})
        end = number(record['next_offset'])
        if record['classification'] == 'cache_define_following_pointer_and_return':
            entry_roles[end].add('cached_body_following_definition')
            entry_parents[end].add(offset)
            queue.append(end)
            break
        if record['classification'] == 'exact_00ff_return':
            break
        offset = end
    else:
        raise AssertionError('No bounded native local invocation return.')
    entries[start] = {'entry_offset': hex(start), 'local_end_exclusive': hex(end), 'local_bytes': end - start, 'command_count': len(local), 'return_kind': record['classification'], 'return_command_offset': record['offset'], 'local_cache_calls': sum(commands[p]['opcode'] == '0x5' for p in local), 'raw_bytes': decoded[start:end].hex(), 'raw_sha256': sha(decoded[start:end]), 'command_offsets': '|'.join(map(hex, local))}
for start, record in entries.items():
    record.update(entry_roles='|'.join(sorted(entry_roles[start])), root_payload_offsets='|'.join(map(hex, sorted(roots.get(start, [])))), defining_command_offsets='|'.join(map(hex, sorted(entry_parents[start]))))

old = rows(prior / 'sample-stream4-commands.csv')
for row in old:
    offset = number(row['offset'])
    record = commands[offset]
    assert u32(number(row['payload_offset']) + 4) in entries
    for field in ('header', 'opcode', 'size_halfwords', 'data_offset', 'data_bytes', 'next_offset', 'count_word', 'count_low14', 'count_high2', 'argument_halfword'):
        if row.get(field):
            assert number(row[field]) == number(str(record[field])), (row, field)

owners = defaultdict(set)
for row in occurrences:
    owners[number(row['command_offset'])].add(number(row['entry_offset']))
for offset, record in commands.items():
    record['local_entry_owners'] = '|'.join(map(hex, sorted(owners[offset])))
definitions = [r for r in commands.values() if r['opcode'] == '0x4' and r['header'] != '0xff']
references = [r for r in commands.values() if r['opcode'] == '0x5' and r['header'] != '0xff']
slots = sorted({r['cache_slot'] for r in definitions + references})
cache_slots = []
cache_candidates = []
for slot in slots:
    defs = sorted((r for r in definitions if r['cache_slot'] == slot), key=lambda row: number(row['offset']))
    refs = sorted((r for r in references if r['cache_slot'] == slot), key=lambda row: number(row['offset']))
    cache_slots.append({'slot': slot, 'definition_count': len(defs), 'reference_count': len(refs), 'definition_offsets_storage_order_only': '|'.join(r['offset'] for r in defs), 'candidate_body_offsets': '|'.join(r['cache_body_offset'] for r in defs), 'reference_offsets_storage_order_only': '|'.join(r['offset'] for r in refs), 'binding': 'unknown; file order is not execution order'})
    for ref in refs:
        for definition in defs:
            body = entries[number(definition['cache_body_offset'])]
            cache_candidates.append({'reference_offset': ref['offset'], 'slot': slot, 'definition_offset': definition['offset'], 'candidate_body_offset': definition['cache_body_offset'], 'candidate_body_end_exclusive': body['local_end_exclusive'], 'reference_local_continuation': ref['local_continuation_offset'], 'bound_runtime_target': False})
cache_sequences = [dict(r, entry_role=entries[number(r['entry_offset'])]['entry_roles'], ordering='local stored command order only; called body and global cache history unresolved') for r in occurrences if r['cache_slot'] != '']

geometry = sorted((r for r in commands.values() if r['classification'] == 'geometry_40_42'), key=lambda row: number(row['offset']))
halfwords = []
for offset, record in sorted(commands.items()):
    for site in range(offset, number(record['next_offset']), 2):
        word = u16(site)
        delta = site - offset
        role = 'header' if delta == 0 else 'size' if delta == 2 and 'size_word' in record else 'count' if delta == 4 and 'count_word' in record else 'argument' if delta == 2 and 'argument_halfword' in record else 'opaque_data'
        halfwords.append({'command_offset': hex(offset), 'opcode': record['opcode'], 'file_offset': hex(site), 'command_byte_delta': delta, 'structural_role': role, 'raw_2_bytes': decoded[site:site + 2].hex(), 'u16': word, 's16': s16(word)})
overlaps = []
ordered_commands = sorted(commands)
for index, first in enumerate(ordered_commands):
    end = number(commands[first]['next_offset'])
    for second in ordered_commands[index + 1:]:
        if second >= end:
            break
        overlaps.append({'first_command': hex(first), 'first_end_exclusive': hex(end), 'second_command': hex(second), 'overlap_bytes': min(end, number(commands[second]['next_offset'])) - second})
write('commands.csv', [commands[p] for p in sorted(commands)])
write('local-invocation-spans.csv', [entries[p] for p in sorted(entries)])
write('command-occurrences.csv', occurrences)
write('command-halfwords.csv', halfwords)
write('geometry-40-42-raw-spans.csv', geometry)
write('cache-local-sequences.csv', cache_sequences)
write('cache-slots.csv', cache_slots, ['slot', 'definition_count', 'reference_count', 'definition_offsets_storage_order_only', 'candidate_body_offsets', 'reference_offsets_storage_order_only', 'binding'])
write('cache-reference-candidates.csv', cache_candidates, ['reference_offset', 'slot', 'definition_offset', 'candidate_body_offset', 'candidate_body_end_exclusive', 'reference_local_continuation', 'bound_runtime_target'])
write('physical-command-overlaps.csv', overlaps, ['first_command', 'first_end_exclusive', 'second_command', 'overlap_bytes'])
write('original-parser-words.csv', selected_words)

digests = []
for path, record in sorted(protected.items(), key=lambda pair: str(pair[0])):
    data = path.read_bytes()
    assert sha(data) == record['sha256_before'] and len(data) == record['bytes_before'], str(path)
    digests.append(dict(record, roles='|'.join(sorted(record['roles'])), bytes_after=len(data), sha256_after=sha(data), unchanged=True))
write('source-digests.csv', digests)
statistics = {'version': 1, 'result': 'passed', 'decoded_bytes': len(decoded), 'decoded_sha256': sha(decoded), 'source_artifacts_verified': len(sources), 'prior_original_instruction_rows_verified': len(native), 'parser_original_instruction_rows': len(selected_words), 'protected_files': len(digests), 'recorded_hashes_verified': sum(bool(r['expected_sha256']) for r in digests), 'all_protected_sources_unchanged': True, 'payload_headers_checked': len(headers), 'nonzero_payload_stream4_entries': len(roots), 'prior_initial_command_rows_crosschecked': len(old), 'local_invocation_entries_including_cached_bodies': len(entries), 'cached_body_entries': sum('cached_body_following_definition' in r['entry_roles'] for r in entries.values()), 'local_return_kinds': dict(Counter(r['return_kind'] for r in entries.values())), 'unique_physical_commands': len(commands), 'local_command_occurrences': len(occurrences), 'unique_command_opcodes': dict(Counter(r['opcode'] for r in commands.values())), 'command_halfword_rows': len(halfwords), 'unique_physical_command_bytes': sum(r['byte_size'] for r in commands.values()), 'physical_command_overlap_pairs': len(overlaps), 'cache_definitions': len(definitions), 'cache_references': len(references), 'cache_slots': len(slots), 'cache_candidate_pairs': len(cache_candidates), 'cache_slots_with_multiple_definitions': sum(r['definition_count'] > 1 for r in cache_slots), 'references_without_in_file_definition': sum(not any(d['cache_slot'] == r['cache_slot'] for d in definitions) for r in references), 'geometry_commands': len(geometry), 'geometry_opcodes': dict(Counter(r['opcode'] for r in geometry)), 'geometry_count_low14': dict(Counter(r['count_low14'] for r in geometry)), 'geometry_count_high2': dict(Counter(r['count_high2'] for r in geometry)), 'geometry_count_bit15_set_commands': sum(r['count_signed16'] < 0 for r in geometry), 'geometry_raw_data_bytes': sum(r['data_bytes'] for r in geometry), 'geometry_original_group_expression_differences_in_sample': sum(r['count_high2'] != r['original_sign_extended_group_expression'] for r in geometry), 'all_u16_group_expression_cases_checked': 65536, 'all_u16_group_expression_differs_from_raw_high2': expression_differences, 'original_parser': '0x8011CCF8 / DOL 0x119CF8', 'offset_space': 'decoded sonicmdl.prs file offsets; never observed runtime addresses', 'script_runs': 'inventory_draw_data_v1.py once', 'runtime_execution_observed': False, 'topology_or_attribute_semantics_inferred': False, 'global_cache_initialized_or_file_order_executed': False, 'engine_files_changed': []}
unknowns = ['Runtime cache contents before invocation, initialization, lifetime, mutations and actual caller order.', 'Whether any static reference is reached and which definition supplies its runtime target.', 'Geometry topology, attribute/material meanings, scratch contents/capacity and runtime state overrides.', 'Full inner geometry grammar, grouped-command execution and exact FIFO transcript.', 'Other files, versions, malformed data and live behavior.']
decisions = ['Stop each native local invocation at exact 00FF or a cache definition, preserving that consumed byte span.', 'Queue the following pointer of each definition as a separate cached-body entry, rather than treating the definition as fallthrough.', 'For references, record the local continuation if the external cache call returns; do not resolve or execute the call.', 'Report every same-slot definition/reference pair as a static candidate only, without assuming file order or initial cache state.', 'Retain geometry 40..42 headers, sizes, raw count fields and every data halfword; do not name topology or attributes.', 'Keep unsigned count high2 separate from the sign-extended original group-state expression.']
summary = dict(statistics, decisions=decisions, unknowns=unknowns, cache_slot_inventory=cache_slots)
summary['artifacts'] = [{'name': p.name, 'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())} for p in sorted(out.iterdir()) if p.is_file() and p.name not in ('summary.md', 'summary.ai.json')]
(out / 'summary.ai.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
lines = ['# Real Sonic second-stream data inventory v1', '', 'One run of inventory_draw_data_v1.py passed. The original decoded bank, frozen original-code digests, original DOL instruction words and prior initial command CSV matched. This is static file evidence, without a rendering or gameplay claim.', '', 'All command and stream addresses in these CSVs are decoded sonicmdl.prs file offsets. Native code addresses are identified separately.', '', 'Machine result: ' + json.dumps(statistics, separators=(',', ':')), '', '## Boundaries and cache evidence', '', '0x8011CCF8 loads a signed header and returns on exact 00FF (0x8011D184/18C). Low-byte command 4 stores the following pointer (0x8011CDA8) and branches to return (0x8011CDB8). Command 5 loads the current global slot and recursively calls the parser (0x8011CDCC/D4), then resumes locally. Accordingly, cached bodies are separate entries; a cache call continuation is conditional on the unresolved call returning.', '', 'The cache table below lists stored addresses in numeric order only. It establishes neither draw order nor a target binding.', '', '| Slot | Definitions | References | Definition offsets | Candidate body offsets | Reference offsets |', '|---:|---:|---:|---|---|---|']
lines.extend(f"| {r['slot']} | {r['definition_count']} | {r['reference_count']} | {r['definition_offsets_storage_order_only']} | {r['candidate_body_offsets']} | {r['reference_offsets_storage_order_only']} |" for r in cache_slots)
lines.extend(['', '## Geometry raw fields', '', 'Geometry 40..42 rows preserve the full encoded span, the raw unsigned size at +2, signed and unsigned count views at +4, and all data halfwords from +6. The native skip is command +4+2*size, following 0x8011CE68 and 0x8011D168..170. The state-operation size at 0x8011CE28 is signed; it is retained separately.', '', 'The count word is loaded with lha at 0x8011CE6C. The group-state expression at 0x8011CF2C rotates its sign-extended value and masks it; it is not universally the raw unsigned high two bits. All 65536 u16 patterns were checked against the corresponding unsigned-right-shift expression. Child record skip expressions such as (param_3 >> 14)&3 are distinct. This report does not replace either expression with an inferred intended count.', '', 'Raw evidence: commands.csv; local-invocation-spans.csv; command-occurrences.csv; command-halfwords.csv; geometry-40-42-raw-spans.csv; cache-local-sequences.csv; cache-slots.csv; cache-reference-candidates.csv; physical-command-overlaps.csv; original-parser-words.csv; source-digests.csv.', '', '## Decisions and unknowns', ''] + ['- ' + item for item in decisions] + ['', 'Unknowns: ' + '; '.join(unknowns), '', 'No engine, repository, original carrier, frozen export, analysis database or processor language was modified. No native execution was performed.'])
(out / 'summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(json.dumps(statistics, separators=(',', ':')))
